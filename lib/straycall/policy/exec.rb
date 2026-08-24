# frozen_string_literal: true

module Straycall
  module Policy
    class Exec
      def initialize
        @default = :allow
        @allowed = []
        @denied = []
      end

      def allow(path)
        validate_path!(path)
        @allowed << normalize(path)
      end

      def deny_elsewhere!
        @default = :deny
      end

      def deny(path)
        validate_path!(path)
        @denied << normalize(path)
      end

      def active?
        @default == :deny || !@denied.empty?
      end

      def allowed?(path)
        path = normalize(path)
        @default == :allow ? !@denied.include?(path) : @allowed.include?(path)
      end

      private

      def validate_path!(path)
        return if path.is_a?(String) && !path.empty? && !path.include?("\0")

        raise ConfigurationError, "executable paths must be non-empty strings without NUL bytes"
      end

      def normalize(path)
        File.realpath(path)
      rescue SystemCallError
        File.expand_path(path)
      end
    end
  end
end
