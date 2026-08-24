# frozen_string_literal: true

require_relative "policy"
require_relative "report/console"
require_relative "report/json"
require_relative "reporter/client"
require_relative "reporter/symbolizer"
require_relative "prompt"
require_relative "handlers/filesystem"
require_relative "handlers/exec"
require "shellwords"

module Straycall
  class Supervisor
    include Handlers::Filesystem
    include Handlers::Exec

    ENDPOINT_SOCKET_DOMAINS = [Socket::AF_UNIX, Socket::AF_INET, Socket::AF_INET6].freeze
    LOCAL_SOCKET_DOMAINS = Socket.const_defined?(:AF_NETLINK, false) ? [Socket.const_get(:AF_NETLINK, false)].freeze : [].freeze
    MMSGHDR_SIZE = 64
    MAX_MMSG = 1024
    REPORT_INTERVAL = 0.1

    attr_reader :violations

    def initialize(config, reporter: nil, console: Report::Console.new, prompt: Prompt.new)
      @config = config
      @reporter = reporter
      @console = console
      @violations = []
      @mutex = Mutex.new
      @reported_locations = {}
      @bound_sockets = {}
      @prompt = prompt
    end

    def run(command)
      supervisor_socket, target_socket = UNIXSocket.pair
      target_socket.close_on_exec = false
      supervisor = Seccomp::Notify.spawn(Policy.seccomp(@config), concurrency: 8) do
        supervisor_socket.close
        environment, argv = command.first.is_a?(Hash) ? [command.first.dup, command.drop(1)] : [{}, command]
        reporter = File.expand_path("target", __dir__)
        inherited_rubyopt = environment.key?("RUBYOPT") ? environment["RUBYOPT"] : ENV["RUBYOPT"]
        environment["STRAYCALL_REPORT_FD"] = target_socket.fileno.to_s
        environment["STRAYCALL_REPORT_PID"] = Process.pid.to_s
        environment["RUBYOPT"] = [Shellwords.escape("-r#{reporter}"), inherited_rubyopt].compact.join(" ")
        exec(environment, *argv)
      end
      target_socket.close
      @reporter = Reporter::Client.new(supervisor_socket)
      register(supervisor)
      status = supervisor.run
      flush_report
      [status, violations]
    ensure
      target_socket&.close unless target_socket&.closed?
      @reporter&.close
    end

    def register(supervisor)
      supervisor.on(:socket) { |request| handle_socket(request) }
      supervisor.on(:connect) { |request| handle_address(request, 1, 2) }
      supervisor.on(:bind) { |request| handle_bind(request) }
      supervisor.on(:listen) { |request| handle_listen(request) }
      supervisor.on(:sendto) { |request| handle_address(request, 4, 5) }
      supervisor.on(:sendmsg) { |request| handle_sendmsg(request) }
      supervisor.on(:sendmmsg) { |request| handle_sendmmsg(request) }
      names = Policy.notification_names(@config)
      cwd = Policy::Filesystem::AT_FDCWD
      supervisor.on(:openat) { |request| handle_openat(request) } if names.include?(:openat)
      supervisor.on(:openat2) { |request| handle_openat2(request) } if names.include?(:openat2)
      supervisor.on(:unlinkat) { |request| handle_path_mutation(request, request.args[0], request.args[1]) } if names.include?(:unlinkat)
      supervisor.on(:mkdirat) { |request| handle_path_mutation(request, request.args[0], request.args[1]) } if names.include?(:mkdirat)
      supervisor.on(:symlinkat) { |request| handle_path_mutation(request, request.args[1], request.args[2]) } if names.include?(:symlinkat)
      supervisor.on(:renameat) { |request| handle_rename(request, *request.args.values_at(0, 1, 2, 3)) } if names.include?(:renameat)
      supervisor.on(:renameat2) { |request| handle_rename(request, *request.args.values_at(0, 1, 2, 3)) } if names.include?(:renameat2)
      supervisor.on(:linkat) { |request| handle_rename(request, *request.args.values_at(0, 1, 2, 3)) } if names.include?(:linkat)
      supervisor.on(:truncate) { |request| handle_path_mutation(request, cwd, request.args[0]) } if names.include?(:truncate)
      supervisor.on(:ftruncate) { |request| handle_fd_mutation(request, request.args[0]) } if names.include?(:ftruncate)
      supervisor.on(:fchmodat) { |request| handle_path_mutation(request, request.args[0], request.args[1]) } if names.include?(:fchmodat)
      supervisor.on(:fchmodat2) { |request| handle_path_mutation(request, request.args[0], request.args[1]) } if names.include?(:fchmodat2)
      supervisor.on(:fchownat) { |request| handle_path_mutation(request, request.args[0], request.args[1]) } if names.include?(:fchownat)
      supervisor.on(:utimensat) { |request| handle_path_mutation(request, request.args[0], request.args[1]) } if names.include?(:utimensat)
      supervisor.on(:copy_file_range) { |request| handle_fd_mutation(request, request.args[2]) } if names.include?(:copy_file_range)
      supervisor.on(:mmap) { |request| handle_mmap(request) } if names.include?(:mmap)
      supervisor.on(:open) { |request| handle_open(request, cwd, request.args[0], request.args[1]) } if names.include?(:open)
      if names.include?(:creat)
        supervisor.on(:creat) do |request|
          flags = Fcntl::O_WRONLY | Fcntl::O_CREAT | Fcntl::O_TRUNC
          handle_open(request, cwd, request.args[0], flags)
        end
      end
      supervisor.on(:unlink) { |request| handle_path_mutation(request, cwd, request.args[0]) } if names.include?(:unlink)
      supervisor.on(:mkdir) { |request| handle_path_mutation(request, cwd, request.args[0]) } if names.include?(:mkdir)
      supervisor.on(:rmdir) { |request| handle_path_mutation(request, cwd, request.args[0]) } if names.include?(:rmdir)
      supervisor.on(:symlink) { |request| handle_path_mutation(request, cwd, request.args[1]) } if names.include?(:symlink)
      %i[chmod chown lchown].each do |name|
        supervisor.on(name) { |request| handle_path_mutation(request, cwd, request.args[0]) } if names.include?(name)
      end
      %i[fchmod fchown].each do |name|
        supervisor.on(name) { |request| handle_fd_mutation(request, request.args[0]) } if names.include?(name)
      end
      supervisor.on(:rename) { |request| handle_rename(request, cwd, request.args[0], cwd, request.args[1]) } if names.include?(:rename)
      supervisor.on(:link) { |request| handle_rename(request, cwd, request.args[0], cwd, request.args[1]) } if names.include?(:link)
      supervisor.on(:execve) { |request| handle_exec(request, nil, 0) } if names.include?(:execve)
      supervisor.on(:execveat) { |request| handle_exec(request, 0, 1) } if names.include?(:execveat)
      supervisor
    end

    def flush_report
      write_report(force: true)
    end

    private

    def handle_socket(request)
      domain = request.args[0]
      allowed = ENDPOINT_SOCKET_DOMAINS.include?(domain) || LOCAL_SOCKET_DOMAINS.include?(domain)
      allowed ||= @config.network.allowed_domain?(domain) && @config.on_violation != :record
      return request.continue! if allowed

      record_violation(request, {type: "socket", domain:, operation: "socket"}, nil)
    end

    def handle_bind(request)
      return request.continue! if @config.network.allow_all? && @config.on_violation != :record

      address = request.read_sockaddr(request.args[1], request.args[2])
      return request.error!(Errno::EPERM) unless request.valid?
      return request.continue!(unsafe: true) unless @config.network.endpoint?(address)
      if @config.network.allowed?(address) && @config.on_violation != :record
        remember_bound_socket(request, address)
        return request.continue!(unsafe: true)
      end

      denied = record_violation(request, target(address), suggestion(address))
      remember_bound_socket(request, address) unless denied
    rescue Seccomp::Notify::MemoryReadError
      record_violation(request, {type: "unknown", host: "?", port: "?"}, nil)
    end

    def handle_listen(request)
      return request.continue! if @config.network.allow_all? && @config.on_violation != :record

      identity = socket_identity(request.tid, request.args[0])
      address = @mutex.synchronize { @bound_sockets[identity] }
      return request.continue! if !address && @config.network.unbound_listen_allowed? && @config.on_violation != :record
      if address && @config.network.allowed?(address) && @config.on_violation != :record
        return request.continue!
      end

      listen_target = address ? target(address).merge(operation: "listen") : {type: "socket", fd: request.args[0], operation: "listen"}
      record_violation(request, listen_target, address && suggestion(address))
    rescue SystemCallError
      record_violation(request, {type: "socket", fd: request.args[0], operation: "listen"}, nil)
    end

    def handle_address(request, address_arg, length_arg)
      return request.continue! if @config.network.allow_all? && @config.on_violation != :record

      if request.syscall == :sendto && (request.args[address_arg].zero? || request.args[length_arg].zero?)
        return request.continue!
      end

      address = request.read_sockaddr(request.args[address_arg], request.args[length_arg])
      return request.error!(Errno::EPERM) unless request.valid?
      return request.continue!(unsafe: true) unless @config.network.endpoint?(address)
      if @config.network.allowed?(address) && @config.on_violation != :record
        return request.continue!(unsafe: true)
      end

      record_violation(request, target(address), suggestion(address))
    rescue Seccomp::Notify::MemoryReadError
      record_violation(request, {type: "unknown", host: "?", port: "?"}, nil)
    end

    def handle_sendmsg(request)
      return request.continue! if @config.network.allow_all? && @config.on_violation != :record

      name, length = request.read(request.args[1], 16).unpack("Q<L<")
      return request.continue!(unsafe: true) if name.zero? || length.zero?

      address = request.read_sockaddr(name, length)
      return request.error!(Errno::EPERM) unless request.valid?
      return request.continue!(unsafe: true) unless @config.network.endpoint?(address)
      if @config.network.allowed?(address) && @config.on_violation != :record
        return request.continue!(unsafe: true)
      end

      record_violation(request, target(address), suggestion(address))
    rescue Seccomp::Notify::MemoryReadError
      record_violation(request, {type: "unknown", host: "?", port: "?"}, nil)
    end

    def handle_sendmmsg(request)
      return request.continue! if @config.network.allow_all? && @config.on_violation != :record

      count = [request.args[2], MAX_MMSG].min
      return request.continue! if count.zero?

      destinations = count.times.filter_map do |index|
        name, length = request.read(request.args[1] + index * MMSGHDR_SIZE, 12).unpack("Q<L<")
        request.read_sockaddr(name, length) unless name.zero? || length.zero?
      end
      return request.error!(Errno::EPERM) unless request.valid?
      destinations.select! { |address| @config.network.endpoint?(address) }
      observed = if @config.on_violation == :record
        destinations
      else
        destinations.reject { |address| @config.network.allowed?(address) }
      end
      return request.continue!(unsafe: true) if observed.empty?
      return record_violation(request, target(observed.first), suggestion(observed.first)) if @config.on_violation == :fail

      denied = observed.map do |address|
        record_violation(request, target(address), suggestion(address), respond: false)
      end.any?
      denied ? request.error!(Errno::EPERM) : request.continue!(unsafe: true)
    rescue Seccomp::Notify::MemoryReadError
      record_violation(request, {type: "unknown", host: "?", port: "?"}, nil)
    end

    def record_violation(request, target, suggestion, respond: true)
      denied = @config.on_violation == :fail ||
        (@config.on_violation == :prompt && !@prompt.allow?(request.syscall, report_target(target)))
      action = denied ? :denied : :allowed
      location = [request.syscall, request.instruction_pointer, target]
      first = @mutex.synchronize { !@reported_locations.key?(location) && (@reported_locations[location] = true) }
      backtrace = @reporter&.backtrace(request.tid) if first && @config.report_backtrace
      origin = Reporter::Symbolizer.call(request.tid, request.instruction_pointer) unless backtrace
      violation = Violation.new(request.syscall, request.tid, target, backtrace, @reporter&.example, action, suggestion, origin)
      @mutex.synchronize { violations << violation }
      @reporter&.notify_violation if denied
      @mutex.synchronize do
        write_report
        @console.violation(violation)
      end
      denied ? request.error!(Errno::EPERM) : request.continue!(unsafe: true) if respond
      denied
    end

    def target(address)
      return {type: "unix", path: address.unix_path} if address.unix?

      {type: "inet", host: address.ip_address, port: address.ip_port}
    end

    def suggestion(address)
      return %(allow_unix #{address.unix_path.inspect}) if address.unix?
      return %(allow_host #{address.ip_address.inspect}) if address.ip_port.zero?

      %(allow_host #{address.ip_address.inspect}, ports: [#{address.ip_port}])
    end

    def write_report(force: false)
      return unless @config.report_path

      now = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      return if !force && @last_report_at && now - @last_report_at < REPORT_INTERVAL

      Report::JSON.new(@config.report_path).write(violations)
      @last_report_at = now
    end

    def report_target(target)
      return target[:path] if target[:path]
      return "socket domain #{target[:domain]}" if target[:domain]
      return "socket fd #{target[:fd]}" if target[:type] == "socket"

      "#{target[:host]}:#{target[:port]}"
    end

    def remember_bound_socket(request, address)
      identity = socket_identity(request.tid, request.args[0])
      @mutex.synchronize do
        # ponytail: observations precede the kernel bind result; use pidfd_getfd + getsockname if this becomes a security boundary.
        @bound_sockets[identity] = address if identity
        @bound_sockets.shift if @bound_sockets.length > 4096
      end
    rescue SystemCallError
      nil
    end

    def socket_identity(tid, fd)
      File.readlink("/proc/#{tid}/fd/#{fd}")[/\Asocket:\[(\d+)\]\z/, 1]
    end
  end
end
