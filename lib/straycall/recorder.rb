# frozen_string_literal: true

require "yaml"
require "fileutils"

module Straycall
  class Recorder
    def initialize(path = ".straycall.recorded.yml", force: false)
      @path = path
      @force = force
    end

    def write(violations)
      network = violations.filter_map do |item|
        next unless item.target[:type] == "inet" && item.target[:host] != "?"

        {"host" => item.target[:host]}.tap do |rule|
          rule["ports"] = [item.target[:port]] if (1..65_535).cover?(item.target[:port])
        end
      end.uniq
      unix = violations.filter_map { |item| item.target[:path] if item.target[:type] == "unix" && item.target[:path] != "?" }.uniq
      domains = violations.filter_map { |item| item.target[:domain] if item.target[:type] == "socket" && item.target[:domain] }.uniq
      unbound_listen = violations.any? { |item| item.target[:type] == "socket" && item.target[:operation] == "listen" }
      writes = violations.filter_map do |item|
        item.target[:path] if item.target[:type] == "file" && item.target[:path] != "?" && item.target[:operation] != "read"
      end.uniq
      executables = violations.filter_map do |item|
        item.target[:path] if item.target[:type] == "exec" && item.target[:path] != "?"
      end.uniq
      policy = {
        "network" => {
          "default" => "deny",
          "allow" => network + unix.map { |path| {"unix" => path} } + domains.map { |domain| {"domain" => domain} },
          "allow_unbound_listen" => unbound_listen
        },
        "write" => {"default" => "deny", "allow" => writes},
        "exec" => {"default" => "deny", "allow" => executables},
        "on_violation" => "fail"
      }
      FileUtils.mkdir_p(File.dirname(@path))
      flags = File::WRONLY | File::CREAT | (@force ? File::TRUNC : File::EXCL)
      File.open(@path, flags, 0o644) { |file| file.write(YAML.dump(policy)) }
      @path
    rescue Errno::EEXIST
      raise ConfigurationError, "refusing to overwrite #{@path}; pass --force to replace it"
    end
  end
end
