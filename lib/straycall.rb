# frozen_string_literal: true

require_relative "straycall/version"
require_relative "straycall/config"
require_relative "straycall/policy"
require_relative "straycall/violation"

module Straycall
  class Error < StandardError; end
  class ConfigurationError < Error; end
  class PathResolutionError < Error; end

  class << self
    attr_writer :config

    def config
      @config ||= Config.new
    end

    def configure
      yield config
      config
    end

    def available?
      return false if ENV["STRAYCALL"] == "0"
      return false unless RUBY_PLATFORM.include?("linux") && RUBY_ENGINE == "ruby"

      require "seccomp/notify"
      Seccomp::Notify.supported? && Seccomp::Notify.features[:continue]
    rescue LoadError, StandardError
      false
    end

    def reset!
      @config = Config.new
      @warned_unavailable = false
    end

    def warn_unavailable!
      return if ENV["STRAYCALL"] == "0" || !RUBY_PLATFORM.include?("linux") || @warned_unavailable

      @warned_unavailable = true
      warn "straycall: seccomp user notifications are unavailable; running unmonitored"
    end
  end
end
