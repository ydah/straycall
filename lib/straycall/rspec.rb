# frozen_string_literal: true

require "rspec/core"
require_relative "../straycall"

module Straycall
  module RSpec
    module_function

    def install
      return unless Straycall.available?

      require "seccomp/notify"
      require_relative "supervisor"
      require_relative "target"
      supervisor_socket, target_socket = UNIXSocket.pair
      guard = Supervisor.new(Straycall.config, reporter: Reporter::Client.new(supervisor_socket))
      Seccomp::Notify.supervise_self(Policy.seccomp(Straycall.config), supervisor: :fork, concurrency: 8) do |instance|
        target_socket.close
        guard.register(instance)
      end
      supervisor_socket.close
      Target.start(target_socket)
      configure_hooks
    end

    def configure_hooks
      ::RSpec.configure do |config|
        config.before do |example|
          ensure_supervisor!
          Target.reporter&.notify_example(
            file: example.metadata[:file_path],
            line: example.metadata[:line_number],
            description: example.full_description
          )
        end
        config.after(:suite) do
          ensure_supervisor!
          raise Error, "syscall violations were detected; see the straycall report" if Target.violation?
        end
      end
    end

    def ensure_supervisor!
      return unless Seccomp::Notify.supervisor_alive? == false

      raise Error, "straycall supervisor stopped; refusing to continue with an unmonitored suite"
    end
  end
end

Straycall::RSpec.install
