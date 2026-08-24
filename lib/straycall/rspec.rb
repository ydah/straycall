# frozen_string_literal: true

require "rspec/core"
require_relative "../straycall"

module Straycall
  module RSpec
    module_function

    def install
      return unless Straycall.available?

      require "seccomp/notify"
      require_relative "in_process"
      require_relative "target"
      return configure_hooks if Seccomp::Notify.supervisor_alive?

      supervisor_socket, target_socket = UNIXSocket.pair
      InProcess.install(Straycall.config, report_socket: supervisor_socket, inherited_report_socket: target_socket)
      Target.start(target_socket)
      configure_hooks
    end

    def configure_hooks
      ::RSpec.configure do |config|
        config.before do |example|
          Straycall::RSpec.ensure_supervisor!
          Target.reporter&.notify_example(
            file: example.metadata[:file_path],
            line: example.metadata[:line_number],
            description: example.full_description
          )
        end
        config.after(:suite) do
          begin
            Straycall::RSpec.ensure_supervisor!
            raise Error, "syscall violations were detected; see the straycall report" if Target.violation?
          ensure
            Target.stop
          end
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
