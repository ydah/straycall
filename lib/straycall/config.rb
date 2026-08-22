# frozen_string_literal: true

require_relative "policy/network"
require_relative "policy/filesystem"
require_relative "policy/exec"

module Straycall
  class Config
    MODES = %i[fail warn record prompt].freeze

    attr_reader :network, :filesystem, :exec
    attr_accessor :report_backtrace, :report_path

    def initialize
      @network = Policy::Network.new
      @filesystem = Policy::Filesystem.new
      @exec = Policy::Exec.new
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

    def allow_write_under(*paths)
      paths.each { |path| filesystem.allow_write_under(path) }
    end

    def deny_write_elsewhere!
      filesystem.deny_write_elsewhere!
    end

    def deny_read(*paths)
      paths.each { |path| filesystem.deny_read(path) }
    end

    def allow_exec(*paths)
      paths.each { |path| exec.allow(path) }
    end

    def deny_exec_elsewhere!
      exec.deny_elsewhere!
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
