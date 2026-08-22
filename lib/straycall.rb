# frozen_string_literal: true

require_relative "straycall/version"
require_relative "straycall/config"
require_relative "straycall/policy"
require_relative "straycall/violation"

module Straycall
  class Error < StandardError; end
  class ConfigurationError < Error; end

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
      Seccomp::Notify.supported?
    rescue LoadError, StandardError
      false
    end

    def reset!
      @config = Config.new
    end
  end
end
