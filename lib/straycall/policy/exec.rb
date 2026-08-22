# frozen_string_literal: true

module Straycall
  module Policy
    class Exec
      def initialize
        @default = :allow
        @allowed = []
      end

      def allow(path)
        @allowed << File.expand_path(path)
      end

      def deny_elsewhere!
        @default = :deny
      end

      def active?
        @default == :deny
      end

      def allowed?(path)
        @default == :allow || @allowed.include?(File.expand_path(path))
      end
    end
  end
end
