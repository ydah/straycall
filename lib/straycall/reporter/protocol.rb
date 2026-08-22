# frozen_string_literal: true

require "json"

module Straycall
  module Reporter
    module Protocol
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
