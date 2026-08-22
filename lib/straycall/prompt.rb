# frozen_string_literal: true

module Straycall
  class Prompt
    def initialize(io = nil)
      @io = io
    end

    def allow?(syscall, target)
      io = @io || File.open("/dev/tty", "r+")
      io.print("straycall: allow #{syscall}(2) → #{target}? [y/N] ")
      io.flush
      %w[y yes].include?(io.gets.to_s.strip.downcase)
    rescue SystemCallError
      false
    ensure
      io&.close if !@io && io && !io.closed?
    end
  end
end
