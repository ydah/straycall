# frozen_string_literal: true

require "yaml"
require "fileutils"

module Straycall
  class Recorder
    def initialize(path = ".straycall.yml")
      @path = path
    end

    def write(violations)
      network = violations.filter_map do |item|
        next unless item.target[:type] == "inet"

        {"host" => item.target[:host], "ports" => [item.target[:port]]}
      end.uniq
      unix = violations.filter_map { |item| item.target[:path] if item.target[:type] == "unix" }.uniq
      writes = violations.filter_map { |item| File.dirname(item.target[:path]) if item.target[:type] == "file" }.uniq
      executables = violations.filter_map { |item| item.target[:path] if item.target[:type] == "exec" }.uniq
      policy = {
        "network" => {"default" => "deny", "allow" => network + unix.map { |path| {"unix" => path} }},
        "write" => {"default" => "deny", "allow" => writes},
        "exec" => {"default" => "deny", "allow" => executables},
        "on_violation" => "fail"
      }
      FileUtils.mkdir_p(File.dirname(@path))
      File.write(@path, YAML.dump(policy))
      @path
    end
  end
end
