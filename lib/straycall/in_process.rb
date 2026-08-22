# frozen_string_literal: true

require "rbconfig"
require "socket"
require "seccomp/notify"

module Straycall
  module InProcess
    module_function

    def install(config, report_socket:, inherited_report_socket:)
      transfer_socket, supervisor_socket = UNIXSocket.pair
      health_reader, health_writer = IO.pipe
      policy = Policy.seccomp(config)
      flags = policy.flags
      flags |= Seccomp::Notify::Constants::SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV if Seccomp::Notify.features[:wait_killable_recv]
      program = Seccomp::Notify::BPF::Builder.new(policy, transfer_fd: transfer_socket.fileno).build

      [supervisor_socket, report_socket, health_writer].each { |io| io.close_on_exec = false }
      inherited_report_socket.close_on_exec = true
      transfer_socket.close_on_exec = true
      encoded_config = Marshal.dump(config).unpack1("H*")
      clean_environment = ENV.keys.grep(/\A(?:BUNDLE|BUNDLER|RUBY(?:OPT|LIB))/).to_h { |name| [name, nil] }
      load_path = [File.expand_path("..", __dir__), File.join(Gem.loaded_specs.fetch("seccomp-notify").full_gem_path, "lib")].join(File::PATH_SEPARATOR)
      pid = Process.spawn(
        clean_environment,
        RbConfig.ruby,
        "-I", load_path,
        File.expand_path("../../exe/straycall-supervisor", __dir__),
        supervisor_socket.fileno.to_s,
        Process.pid.to_s,
        encoded_config,
        report_socket.fileno.to_s,
        health_writer.fileno.to_s,
        supervisor_socket.fileno => supervisor_socket.fileno,
        report_socket.fileno => report_socket.fileno,
        health_writer.fileno => health_writer.fileno,
        pgroup: true
      )
      supervisor_socket.close
      report_socket.close
      health_writer.close
      unless IO.select([health_reader], nil, nil, 5) && health_reader.read(1) == "R"
        raise Error, "straycall supervisor failed to start"
      end
      health_reader.close_on_exec = false
      ENV["SECCOMP_NOTIFY_HEALTH_FD"] = health_reader.fileno.to_s
      @health_reader = health_reader

      result = Seccomp::Notify::Libc.prctl(Seccomp::Notify::Constants::PR_SET_PTRACER, pid)
      raise SystemCallError.new("prctl(PR_SET_PTRACER)", Fiddle.last_error) if result.negative?

      listener = Seccomp::Notify::Filter.install!(program, flags:)
      Seccomp::Notify::FdPassing.send_fd(transfer_socket, listener)
      listener.close
      transfer_socket.close
      unless IO.select([health_reader], nil, nil, 5) && health_reader.read(1) == "S"
        raise Error, "straycall supervisor failed to initialize"
      end
      Process.detach(pid)
      pid
    rescue StandardError
      listener&.close unless listener&.closed?
      [transfer_socket, supervisor_socket, report_socket, health_reader, health_writer].each do |io|
        io&.close unless io&.closed?
      end
      if pid
        Process.kill("KILL", pid) rescue nil
        Process.waitpid(pid) rescue nil
      end
      raise
    end
  end
end
