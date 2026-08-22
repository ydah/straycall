# frozen_string_literal: true

require "ipaddr"
require "socket"

module Straycall
  module Policy
    class Network
      Rule = Struct.new(:address, :ports)

      def initialize
        @default = :deny
        @inet = []
        @unix = []
      end

      def deny!
        @default = :deny
      end

      def allow!
        @default = :allow
      end

      def allow_loopback(ports: nil)
        add_inet(IPAddr.new("127.0.0.0/8"), ports)
        add_inet(IPAddr.new("::1"), ports)
      end

      def allow_unix(path)
        @unix << File.expand_path(path)
      end

      def allow_host(host, ports: nil)
        Addrinfo.getaddrinfo(host, nil, nil, Socket::SOCK_STREAM).filter_map do |address|
          add_inet(IPAddr.new(address.ip_address), ports) if address.ip?
        end
      rescue SocketError => error
        raise ConfigurationError, "cannot resolve host #{host.inspect}: #{error.message}"
      end

      def allowed?(address)
        return true if @default == :allow
        return @unix.any? { |prefix| address.unix_path.start_with?(prefix) } if address.unix?
        return false unless address.ip?

        ip = IPAddr.new(address.ip_address.split("%", 2).first)
        @inet.any? do |rule|
          rule.address.include?(ip) && (rule.ports.nil? || rule.ports.any? { |port| port === address.ip_port })
        end
      end

      def deny_all_inet?
        @default == :deny && @inet.empty?
      end

      private

      def add_inet(address, ports)
        @inet << Rule.new(address, normalize_ports(ports))
      end

      def normalize_ports(ports)
        return if ports.nil?

        Array(ports).each do |port|
          next if port.is_a?(Range) && port.begin.is_a?(Integer) && port.end.is_a?(Integer) && port.begin.between?(1, port.end) && port.end <= 65_535
          next if port.is_a?(Integer) && (1..65_535).cover?(port)

          raise ConfigurationError, "ports must contain integers or ranges between 1 and 65535"
        end.freeze
      end
    end
  end
end
