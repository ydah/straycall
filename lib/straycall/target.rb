# frozen_string_literal: true

require_relative "reporter/thread_reporter"

module Straycall
  module Target
    module_function

    def start(socket = nil)
      socket ||= IO.for_fd(Integer(ENV.fetch("STRAYCALL_REPORT_FD")), autoclose: true)
      @reporter = Reporter::ThreadReporter.new(socket).start
    rescue KeyError, ArgumentError
      nil
    end

    def reporter
      @reporter
    end

    def violation?
      @reporter&.violation? || false
    end
  end
end

Straycall::Target.start if ENV["STRAYCALL_REPORT_FD"]
