# frozen_string_literal: true

module Straycall
  module Report
    class Console
      def initialize(io = $stderr)
        @io = io
      end

      def violation(item)
        @io.puts("straycall: #{item.syscall}(2) → #{target(item.target)}")
        @io.puts("  #{item.example[:file]}:#{item.example[:line]} #{item.example[:description]}") if item.example
        Array(item.backtrace).each { |line| @io.puts("    #{line}") }
        @io.puts("  origin: #{item.origin}") if item.origin
        @io.puts("  hint: #{item.suggestion}") if item.suggestion
      end

      private

      def target(value)
        return value[:path] if %w[unix file exec].include?(value[:type])
        return "socket domain #{value[:domain]}" if value[:domain]
        return "socket fd #{value[:fd]}" if value[:type] == "socket"

        "#{value[:host]}:#{value[:port]}"
      end
    end
  end
end
