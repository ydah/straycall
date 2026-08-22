# frozen_string_literal: true

require_relative "policy"
require_relative "report/console"
require_relative "report/json"
require_relative "reporter/client"
require_relative "reporter/symbolizer"

module Straycall
  class Supervisor
    attr_reader :violations

    def initialize(config, reporter: nil, console: Report::Console.new)
      @config = config
      @reporter = reporter
      @console = console
      @violations = []
      @mutex = Mutex.new
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
      supervisor
    end

    private

    def handle_socket(request)
      request.continue!
    end

    def handle_address(request, address_arg, length_arg)
      address = request.read_sockaddr(request.args[address_arg], request.args[length_arg])
      return request.error!(Errno::EPERM) unless request.valid?
      return request.continue!(unsafe: true) if @config.network.allowed?(address)

      reject(request, target(address), suggestion(address))
    rescue Seccomp::Notify::MemoryReadError
      reject(request, {type: "unknown", host: "?", port: "?"}, nil)
    end

    def reject(request, target, suggestion)
      action = @config.on_violation == :fail ? :denied : :allowed
      backtrace = @reporter&.backtrace(request.tid) if @config.report_backtrace
      origin = Reporter::Symbolizer.call(request.tid, request.instruction_pointer) unless backtrace
      violation = Violation.new(request.syscall, request.tid, target, backtrace, @reporter&.example, action, suggestion, origin)
      @mutex.synchronize do
        violations << violation
        write_report
      end
      @console.violation(violation)
      @reporter&.notify_violation if action == :denied
      @config.on_violation == :fail ? request.error!(Errno::EPERM) : request.continue!(unsafe: true)
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
  end
end
