# frozen_string_literal: true

require "optparse"
require "tmpdir"
require_relative "../straycall"

module Straycall
  class CLI
    def self.start(argv = ARGV)
      new(argv).run
    end

    def initialize(argv)
      @argv = argv.dup
      @config_actions = []
    end

    def run
      parse!
      return exec(*@argv) unless Straycall.available?

      require "seccomp/notify"
      require_relative "supervisor"
      status, violations = Supervisor.new(Straycall.config).run(@argv)
      if Straycall.config.on_violation == :record
        require_relative "recorder"
        Recorder.new(@policy_path, force: @force).write(violations)
      end
      return 1 if violations.any? { |violation| violation.action == :denied }

      child_exit_code(status)
    rescue OptionParser::ParseError, ConfigurationError => error
      warn "straycall: #{error.message}"
      64
    end

    private

    def child_exit_code(status)
      return 1 unless status

      status.signaled? ? 128 + status.termsig : status.exitstatus
    end

    def parse!
      parser = OptionParser.new do |options|
        options.banner = "Usage: straycall [options] -- command [args]"
        options.on("--config PATH") { |value| @config_path = value }
        options.on("--[no-]backtrace") { |value| @config_actions << ->(config) { config.report_backtrace = value } }
        options.on("--report-path PATH") { |value| @config_actions << ->(config) { config.report_path = value } }
        options.on("--record") { @config_actions << ->(config) { config.on_violation = :record } }
        options.on("--policy-path PATH") { |value| @policy_path = value }
        options.on("--force") { @force = true }
        options.on("--warn") { @config_actions << ->(config) { config.on_violation = :warn } }
        options.on("--prompt") { @config_actions << ->(config) { config.on_violation = :prompt } }
        options.on("--preset NAME") { |value| @config_actions << ->(config) { apply_preset(config, value) } }
      end
      parser.order!(@argv)
      @argv.shift if @argv.first == "--"
      raise OptionParser::MissingArgument, "command" if @argv.empty?
      @policy_path ||= ".straycall.recorded.yml"
      Straycall.config = @config_path ? Config.load(@config_path) : Straycall.config
      @config_actions.each { |action| action.call(Straycall.config) }
    end

    def apply_preset(config, name)
      raise ConfigurationError, "unknown preset: #{name}" unless name == "bundle-install"

      config.on_violation = :prompt
      config.allow_write_under(Dir.pwd, Dir.tmpdir, Gem.dir)
      config.deny_write_elsewhere!
    end
  end
end
