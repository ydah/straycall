# frozen_string_literal: true

require_relative "protocol"

module Straycall
  module Reporter
    class ThreadReporter
      attr_reader :thread

      def initialize(socket)
        @socket = socket
        @reader = Protocol::Reader.new(socket)
        @write_mutex = Mutex.new
        @violation = false
      end

      def start
        return self unless RUBY_ENGINE == "ruby" && Thread.current.respond_to?(:native_thread_id)

        ready = Queue.new
        @thread = Thread.new { ready << true; run }
        @thread.name = "straycall-reporter" if @thread.respond_to?(:name=)
        ready.pop
        self
      end

      def notify_example(example)
        write(Protocol.example(example))
      end

      def violation?
        return true if @violation

        pending = @socket.recv_nonblock(Protocol::Reader::LIMIT, Socket::MSG_PEEK, exception: false)
        pending.is_a?(String) && pending.match?(/(?:\A|\n)VIOLATION\n/)
      rescue IOError, SystemCallError
        false
      end

      def stop
        @socket.close unless @socket.closed?
        @thread&.join(0.2)
      end

      private

      def run
        while (line = @reader.read)
          type, tid = Protocol.parse(line)
          case type
          when :backtrace
            target = Thread.list.find { |candidate| candidate != Thread.current && candidate.native_thread_id == tid }
            write(Protocol.backtrace_response(tid, target&.backtrace))
          when :violation
            @violation = true
            write("OK\n")
          when :sync
            write("OK\n")
          end
        end
      rescue IOError, SystemCallError
        nil
      end

      def write(message)
        @write_mutex.synchronize { @socket.write(message) }
      rescue IOError, SystemCallError
        nil
      end
    end
  end
end
