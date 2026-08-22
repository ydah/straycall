# frozen_string_literal: true

require_relative "policy/network"

module Straycall
  class Config
    MODES = %i[fail warn record prompt].freeze

    attr_reader :network
    attr_accessor :report_backtrace, :report_path

    def initialize
      @network = Policy::Network.new
      @on_violation = :fail
      @report_backtrace = true
      @report_path = nil
    end

    def deny_network!
      network.deny!
    end

    def allow_loopback(ports: nil)
      network.allow_loopback(ports:)
    end

    def allow_unix(path)
      network.allow_unix(path)
    end

    def allow_host(host, ports: nil)
      network.allow_host(host, ports:)
    end

    def on_violation
      @on_violation
    end

    def on_violation=(mode)
      mode = mode.to_sym
      raise ConfigurationError, "on_violation must be one of: #{MODES.join(", ")}" unless MODES.include?(mode)

      @on_violation = mode
    end
  end
end
