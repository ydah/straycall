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
      require_relative "in_process"
      require_relative "target"
      supervisor_socket, target_socket = UNIXSocket.pair
      InProcess.install(Straycall.config, report_socket: supervisor_socket, inherited_report_socket: target_socket)
      Target.start(target_socket)
      ::Minitest::Test.prepend(Hooks)
      ::Minitest.after_run do
        begin
          Straycall::Minitest.ensure_supervisor!
          raise Error, "syscall violations were detected; see the straycall report" if Target.violation?
        ensure
          Target.stop
        end
      end
    end

    def ensure_supervisor!
      return unless Seccomp::Notify.supervisor_alive? == false

      raise Error, "straycall supervisor stopped; refusing to continue with an unmonitored suite"
    end
  end
end

Straycall::Minitest.install
