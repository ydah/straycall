# frozen_string_literal: true

require_relative "policy"
require_relative "report/console"
require_relative "report/json"
require_relative "reporter/client"
require_relative "reporter/symbolizer"
require_relative "prompt"
require_relative "handlers/filesystem"
require_relative "handlers/exec"

module Straycall
  class Supervisor
    include Handlers::Filesystem
    include Handlers::Exec

    attr_reader :violations

    def initialize(config, reporter: nil, console: Report::Console.new, prompt: Prompt.new)
      @config = config
      @reporter = reporter
      @console = console
      @violations = []
      @mutex = Mutex.new
      @reported_locations = {}
      @prompt = prompt
    end

    def run(command)
      supervisor_socket, target_socket = UNIXSocket.pair
      target_socket.close_on_exec = false
      supervisor = Seccomp::Notify.spawn(Policy.seccomp(@config), concurrency: 8) do
        supervisor_socket.close
        ENV["STRAYCALL_REPORT_FD"] = target_socket.fileno.to_s
        reporter = File.expand_path("target", __dir__)
        ENV["RUBYOPT"] = ["-r#{reporter}", ENV["RUBYOPT"]].compact.join(" ")
        exec(*command)
      end
      target_socket.close
      @reporter = Reporter::Client.new(supervisor_socket)
      register(supervisor)
      status = supervisor.run
      write_report
      [status, violations]
    ensure
      target_socket&.close unless target_socket&.closed?
      @reporter&.close
    end

    def register(supervisor)
      supervisor.on(:socket) { |request| handle_socket(request) }
      supervisor.on(:connect) { |request| handle_address(request, 1, 2) }
      supervisor.on(:sendto) { |request| handle_address(request, 4, 5) }
      names = Policy.notification_names(@config)
      supervisor.on(:openat) { |request| handle_openat(request) } if names.include?(:openat)
      supervisor.on(:openat2) { |request| handle_openat2(request) } if names.include?(:openat2)
      supervisor.on(:unlinkat) { |request| handle_path_mutation(request, request.args[0], request.args[1]) } if names.include?(:unlinkat)
      supervisor.on(:mkdirat) { |request| handle_path_mutation(request, request.args[0], request.args[1]) } if names.include?(:mkdirat)
      supervisor.on(:renameat) { |request| handle_rename(request, *request.args.values_at(0, 1, 2, 3)) } if names.include?(:renameat)
      supervisor.on(:renameat2) { |request| handle_rename(request, *request.args.values_at(0, 1, 2, 3)) } if names.include?(:renameat2)
      cwd = Policy::Filesystem::AT_FDCWD
      supervisor.on(:unlink) { |request| handle_path_mutation(request, cwd, request.args[0]) } if names.include?(:unlink)
      supervisor.on(:mkdir) { |request| handle_path_mutation(request, cwd, request.args[0]) } if names.include?(:mkdir)
      supervisor.on(:rename) { |request| handle_rename(request, cwd, request.args[0], cwd, request.args[1]) } if names.include?(:rename)
      supervisor.on(:execve) { |request| handle_exec(request, nil, 0) } if names.include?(:execve)
      supervisor.on(:execveat) { |request| handle_exec(request, 0, 1) } if names.include?(:execveat)
      supervisor
    end

    private

    def handle_socket(request)
      request.continue!
    end

    def handle_address(request, address_arg, length_arg)
      address = request.read_sockaddr(request.args[address_arg], request.args[length_arg])
      return request.error!(Errno::EPERM) unless request.valid?
      if @config.network.allowed?(address) && @config.on_violation != :record
        return request.continue!(unsafe: true)
      end

      record_violation(request, target(address), suggestion(address))
    rescue Seccomp::Notify::MemoryReadError
      record_violation(request, {type: "unknown", host: "?", port: "?"}, nil)
    end

    def record_violation(request, target, suggestion)
      denied = @config.on_violation == :fail ||
        (@config.on_violation == :prompt && !@prompt.allow?(request.syscall, report_target(target)))
      action = denied ? :denied : :allowed
      location = [request.syscall, request.instruction_pointer, target]
      first = @mutex.synchronize { !@reported_locations.key?(location) && (@reported_locations[location] = true) }
      backtrace = @reporter&.backtrace(request.tid) if first && @config.report_backtrace
      origin = Reporter::Symbolizer.call(request.tid, request.instruction_pointer) unless backtrace
      violation = Violation.new(request.syscall, request.tid, target, backtrace, @reporter&.example, action, suggestion, origin)
      @mutex.synchronize do
        violations << violation
        write_report
      end
      @console.violation(violation)
      @reporter&.notify_violation if denied
      denied ? request.error!(Errno::EPERM) : request.continue!(unsafe: true)
    end

    def target(address)
      return {type: "unix", path: address.unix_path} if address.unix?

      {type: "inet", host: address.ip_address, port: address.ip_port}
    end

    def suggestion(address)
      return %(allow_unix #{address.unix_path.inspect}) if address.unix?

      %(allow_host #{address.ip_address.inspect}, ports: [#{address.ip_port}])
    end

    def write_report
      Report::JSON.new(@config.report_path).write(violations) if @config.report_path
    end

    def report_target(target)
      return target[:path] if target[:path]

      "#{target[:host]}:#{target[:port]}"
    end
  end
end
