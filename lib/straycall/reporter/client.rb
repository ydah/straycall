# frozen_string_literal: true

require_relative "protocol"

module Straycall
  module Reporter
    class Client
      def initialize(socket, timeout: 0.2)
        @socket = socket
        @reader = Protocol::Reader.new(socket)
        @timeout = timeout
        @mutex = Mutex.new
        @alive = true
      end

      def example
        return @example unless @alive

        @mutex.synchronize do
          @socket.write(Protocol.sync_request)
          read_ack
          @example
        end
      rescue IOError, SystemCallError
        @alive = false
        @example
      end

      def backtrace(tid)
        return unless @alive

        @mutex.synchronize do
          @socket.write(Protocol.backtrace_request(tid))
          read_backtrace(tid)
        end
      rescue IOError, SystemCallError
        @alive = false
        nil
      end

      def notify_violation
        return unless @alive

        @mutex.synchronize do
          @socket.write("VIOLATION\n")
          read_ack
        end
      rescue IOError, SystemCallError
        @alive = false
      end

      def close
        @socket.close unless @socket.closed?
      end

      private

      def read_backtrace(tid)
        deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + @timeout
        loop do
          remaining = deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
          return if remaining <= 0

          line = @reader.read(timeout: remaining)
          unless line
            @alive = false
            return
          end

          type, value, payload = Protocol.parse(line)
          case type
          when :backtrace
            return payload if value == tid
          when :example
            @example = value
          end
        end
      end

      def read_ack
        deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + @timeout
        loop do
          remaining = deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
          return if remaining <= 0

          line = @reader.read(timeout: remaining)
          unless line
            @alive = false
            return
          end

          type, value = Protocol.parse(line)
          return if type == :ack

          @example = value if type == :example
        end
      end
    end
  end
end
