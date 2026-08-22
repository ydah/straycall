# frozen_string_literal: true

require_relative "policy"
require_relative "report/console"

module Straycall
  class Supervisor
    attr_reader :violations

    def initialize(config, console: Report::Console.new)
      @config = config
      @console = console
      @violations = []
    end

    def run(command)
      supervisor = Seccomp::Notify.spawn(Policy.seccomp(@config), concurrency: 8) { exec(*command) }
      register(supervisor)
      [supervisor.run, violations]
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
      violation = Violation.new(request.syscall, request.tid, target, nil, nil, action, suggestion, nil)
      violations << violation
      @console.violation(violation)
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
  end
end
