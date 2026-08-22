# frozen_string_literal: true

require_relative "protocol"

module Straycall
  module Reporter
    class ThreadReporter
      attr_reader :thread

      def initialize(socket)
        @socket = socket
        @write_mutex = Mutex.new
        @violation = false
      end

      def start
        return self unless RUBY_ENGINE == "ruby" && Thread.current.respond_to?(:native_thread_id)

        @thread = Thread.new { run }
        @thread.name = "straycall-reporter" if @thread.respond_to?(:name=)
        self
      end

      def notify_example(example)
        write(Protocol.example(example))
      end

      def violation?
        @violation
      end

      def stop
        @socket.close unless @socket.closed?
        @thread&.join(0.2)
      end

      private

      def run
        buffer = String.new(capacity: 64 * 1024)
        while (line = @socket.gets)
          buffer.replace(line)
          type, tid = Protocol.parse(buffer)
          case type
          when :backtrace
            target = Thread.list.find { |candidate| candidate != Thread.current && candidate.native_thread_id == tid }
            write(Protocol.backtrace_response(tid, target&.backtrace))
          when :violation
            @violation = true
            write("OK\n")
          end
        end
      rescue IOError, SystemCallError
        nil
      ensure
        @socket.close unless @socket.closed?
      end

      def write(message)
        @write_mutex.synchronize { @socket.write(message) }
      rescue IOError, SystemCallError
        nil
      end
    end
  end
end
