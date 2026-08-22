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
        @allowed << File.expand_path(path)
      end

      def deny_elsewhere!
        @default = :deny
      end

      def deny(path)
        @denied << File.expand_path(path)
      end

      def active?
        @default == :deny || !@denied.empty?
      end

      def allowed?(path)
        path = File.expand_path(path)
        @default == :allow ? !@denied.include?(path) : @allowed.include?(path)
      end
    end
  end
end
