# frozen_string_literal: true

require "yaml"
require_relative "policy/network"
require_relative "policy/filesystem"
require_relative "policy/exec"

module Straycall
  class Config
    MODES = %i[fail warn record prompt].freeze
    TOP_LEVEL_KEYS = %w[network write exec on_violation report_backtrace report_path].freeze

    def self.load(path)
      data = YAML.safe_load_file(path, permitted_classes: [], aliases: false) || {}
      raise ConfigurationError, "configuration must be a mapping" unless data.is_a?(Hash)

      unknown = data.keys.map(&:to_s) - TOP_LEVEL_KEYS
      raise ConfigurationError, "unknown configuration keys: #{unknown.join(", ")}" unless unknown.empty?

      new.tap { |config| config.apply(data) }
    rescue Psych::Exception => error
      raise ConfigurationError, "invalid YAML: #{error.message}"
    rescue SystemCallError => error
      raise ConfigurationError, "cannot read configuration: #{error.message}"
    end

    attr_reader :network, :filesystem, :exec
    attr_reader :report_backtrace, :report_path

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

    def deny_exec(*paths)
      paths.each { |path| exec.deny(path) }
    end

    def on_violation
      @on_violation
    end

    def report_backtrace=(value)
      raise ConfigurationError, "report_backtrace must be true or false" unless [true, false].include?(value)

      @report_backtrace = value
    end

    def report_path=(value)
      unless value.nil? || (value.is_a?(String) && !value.empty?)
        raise ConfigurationError, "report_path must be a non-empty string or nil"
      end

      @report_path = value
    end

    def on_violation=(mode)
      mode = mode.to_sym if mode.respond_to?(:to_sym)
      raise ConfigurationError, "on_violation must be one of: #{MODES.join(", ")}" unless MODES.include?(mode)

      @on_violation = mode
    end

    def apply(data)
      apply_network(section(data, "network")) if key?(data, "network")
      apply_write(section(data, "write")) if key?(data, "write")
      apply_exec(section(data, "exec")) if key?(data, "exec")
      self.on_violation = fetch(data, "on_violation") if key?(data, "on_violation")
      self.report_backtrace = boolean(data, "report_backtrace") if key?(data, "report_backtrace")
      if key?(data, "report_path")
        raise ConfigurationError, "report_path must be a string" unless fetch(data, "report_path").is_a?(String)

        self.report_path = fetch(data, "report_path")
      end
      self
    end

    private

    def apply_network(data)
      validate_keys!(data, %w[default allow], "network")
      default = key?(data, "default") ? fetch(data, "default") : "deny"
      raise ConfigurationError, "network.default must be allow or deny" unless %w[allow deny].include?(default)

      default == "allow" ? network.allow! : network.deny!
      array(data, "allow").each do |rule|
        raise ConfigurationError, "network allow rules must be mappings" unless rule.is_a?(Hash)
        validate_keys!(rule, %w[host ports unix], "network allow rule")

        unix = key?(rule, "unix")
        host = key?(rule, "host")
        raise ConfigurationError, "network allow rule requires exactly one of host or unix" if unix == host

        if unix
          raise ConfigurationError, "unix network allow rules cannot specify ports" if key?(rule, "ports")

          path = fetch(rule, "unix")
          allow_unix(string(path, "unix"))
        else
          address = fetch(rule, "host")
          allow_host(string(address, "host"), ports: fetch(rule, "ports"))
        end
      end
    end

    def apply_write(data)
      validate_keys!(data, %w[default allow deny_read], "write")
      default = key?(data, "default") ? fetch(data, "default") : "allow"
      raise ConfigurationError, "write.default must be allow or deny" unless %w[allow deny].include?(default)

      array(data, "allow").each { |path| allow_write_under(string(path, "write.allow")) }
      deny_write_elsewhere! if default == "deny"
      array(data, "deny_read").each { |path| deny_read(string(path, "write.deny_read")) }
    end

    def apply_exec(data)
      validate_keys!(data, %w[default allow deny], "exec")
      default = key?(data, "default") ? fetch(data, "default") : "allow"
      raise ConfigurationError, "exec.default must be allow or deny" unless %w[allow deny].include?(default)

      array(data, "allow").each { |path| allow_exec(string(path, "exec.allow")) }
      array(data, "deny").each { |path| deny_exec(string(path, "exec.deny")) }
      deny_exec_elsewhere! if default == "deny"
    end

    def section(data, key)
      value = fetch(data, key)
      raise ConfigurationError, "#{key} must be a mapping" unless value.is_a?(Hash)

      value
    end

    def array(data, key)
      value = key?(data, key) ? fetch(data, key) : []
      raise ConfigurationError, "#{key} must be an array" unless value.is_a?(Array)

      value
    end

    def boolean(data, key)
      value = fetch(data, key)
      raise ConfigurationError, "#{key} must be true or false" unless [true, false].include?(value)

      value
    end

    def string(value, label)
      raise ConfigurationError, "#{label} must be a string" unless value.is_a?(String)

      value
    end

    def validate_keys!(data, allowed, label)
      unknown = data.keys.map(&:to_s) - allowed
      raise ConfigurationError, "unknown #{label} keys: #{unknown.join(", ")}" unless unknown.empty?
    end

    def fetch(data, key)
      return data[key] if data.key?(key)

      data[key.to_sym]
    end

    def key?(data, key)
      data.key?(key) || data.key?(key.to_sym)
    end
  end
end
