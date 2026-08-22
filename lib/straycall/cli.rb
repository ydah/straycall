# frozen_string_literal: true

require "optparse"
require_relative "../straycall"

module Straycall
  class CLI
    def self.start(argv = ARGV)
      new(argv).run
    end

    def initialize(argv)
      @argv = argv.dup
    end

    def run
      parse!
      return exec(*@argv) unless Straycall.available?

      require "seccomp/notify"
      require_relative "supervisor"
      status, violations = Supervisor.new(Straycall.config).run(@argv)
      violations.any? && Straycall.config.on_violation == :fail ? 1 : status&.exitstatus.to_i
    rescue OptionParser::ParseError, ConfigurationError => error
      warn "straycall: #{error.message}"
      64
    end

    private

    def parse!
      parser = OptionParser.new do |options|
        options.banner = "Usage: straycall [options] -- command [args]"
        options.on("--[no-]backtrace") { |value| Straycall.config.report_backtrace = value }
        options.on("--report-path PATH") { |value| Straycall.config.report_path = value }
        options.on("--record") { Straycall.config.on_violation = :record }
        options.on("--warn") { Straycall.config.on_violation = :warn }
      end
      parser.order!(@argv)
      @argv.shift if @argv.first == "--"
      raise OptionParser::MissingArgument, "command" if @argv.empty?
    end
  end
end
