# frozen_string_literal: true

module Straycall
  Violation = Struct.new(:syscall, :tid, :target, :backtrace, :example, :action, :suggestion, :origin) do
    def to_h
      {syscall: syscall.to_s, tid:, example:, target:, backtrace:, action: action.to_s, suggestion:, origin:}.compact
    end
  end
end
