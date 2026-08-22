# frozen_string_literal: true

require "fileutils"
require "json"

module Straycall
  module Report
    class JSON
      def initialize(path)
        @path = path
      end

      def write(violations)
        FileUtils.mkdir_p(File.dirname(@path))
        File.write(@path, ::JSON.pretty_generate(version: 1, violations: violations.map(&:to_h)) << "\n")
      end
    end
  end
end
