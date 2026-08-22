# frozen_string_literal: true

require "minitest"
require_relative "../straycall"

module Straycall
  module Minitest
    module Hooks
      def before_setup
        Straycall::Minitest.ensure_supervisor!
        file, line = method(name).source_location
        Target.reporter&.notify_example(file:, line:, description: "#{self.class}##{name}")
        super
      end
    end

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
      ::Minitest::Test.prepend(Hooks)
      ::Minitest.after_run do
        ensure_supervisor!
        raise Error, "syscall violations were detected; see the straycall report" if Target.violation?
      end
    end

    def ensure_supervisor!
      return unless Seccomp::Notify.supervisor_alive? == false

      raise Error, "straycall supervisor stopped; refusing to continue with an unmonitored suite"
    end
  end
end

Straycall::Minitest.install
