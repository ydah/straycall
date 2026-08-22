# frozen_string_literal: true

require "json"

module Straycall
  module Reporter
    module Protocol
      class Reader
        LIMIT = 64 * 1024

        def initialize(socket)
          @socket = socket
          @buffer = String.new(capacity: LIMIT)
          @chunk = String.new(capacity: 4096)
        end

        def read(timeout: nil)
          deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout if timeout
          loop do
            if (newline = @buffer.index("\n"))
              return @buffer.slice!(0, newline + 1)
            end
            if deadline
              remaining = deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
              return if remaining <= 0 || !IO.select([@socket], nil, nil, remaining)
            end

            @socket.readpartial(4096, @chunk)
            raise IOError, "reporter message exceeds #{LIMIT} bytes" if @buffer.bytesize + @chunk.bytesize > LIMIT

            @buffer << @chunk
          end
        rescue EOFError
          nil
        end
      end

      module_function

      def backtrace_request(tid)
        "BT #{Integer(tid)}\n"
      end

      def backtrace_response(tid, backtrace)
        payload = backtrace ? JSON.generate(backtrace) : "-"
        "BT #{Integer(tid)} #{payload}\n"
      end

      def example(value)
        "EXAMPLE #{JSON.generate(value)}\n"
      end

      def sync_request
        "SYNC\n"
      end

      def parse(line)
        type, rest = line.to_s.chomp.split(" ", 2)
        case type
        when "BT"
          tid, payload = rest.to_s.split(" ", 2)
          [:backtrace, Integer(tid), payload && payload != "-" ? JSON.parse(payload) : nil]
        when "EXAMPLE"
          [:example, JSON.parse(rest, symbolize_names: true)]
        when "VIOLATION"
          [:violation]
        when "SYNC"
          [:sync]
        when "OK"
          [:ack]
        else
          [:unknown]
        end
      rescue ArgumentError, JSON::ParserError
        [:unknown]
      end
    end
  end
end
