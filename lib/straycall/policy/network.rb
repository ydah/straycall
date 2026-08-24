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
        @domains = []
        @allow_unbound_listen = false
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
        unless path.is_a?(String) && !path.empty? && !path.include?("\0")
          raise ConfigurationError, "Unix socket paths must be non-empty strings without NUL bytes"
        end

        @unix << File.expand_path(path)
      end

      def allow_host(host, ports: nil)
        unless host.is_a?(String) && !host.empty? && !host.include?("\0")
          raise ConfigurationError, "hosts must be non-empty strings without NUL bytes"
        end

        Addrinfo.getaddrinfo(host, nil, nil, Socket::SOCK_STREAM).filter_map do |address|
          add_inet(IPAddr.new(address.ip_address), ports) if address.ip?
        end
      rescue SocketError => error
        raise ConfigurationError, "cannot resolve host #{host.inspect}: #{error.message}"
      end

      def allow_domain(domain)
        raise ConfigurationError, "socket domains must be non-negative integers" unless domain.is_a?(Integer) && domain >= 0

        @domains << domain
      end

      def allow_unbound_listen!
        @allow_unbound_listen = true
      end

      def allowed_domain?(domain)
        @default == :allow || @domains.include?(domain)
      end

      def unbound_listen_allowed?
        @default == :allow || @allow_unbound_listen
      end

      def allowed?(address)
        return true if @default == :allow
        if address.unix?
          path = address.unix_path
          return @unix.any? { |prefix| path == prefix || path.start_with?(File.join(prefix, "")) }
        end
        return false unless address.ip?

        ip = IPAddr.new(address.ip_address.split("%", 2).first)
        ip = ip.native if ip.ipv4_mapped?
        @inet.any? do |rule|
          rule.address.include?(ip) && (rule.ports.nil? || rule.ports.any? { |port| port === address.ip_port })
        end
      end

      def endpoint?(address)
        address.unix? || address.ip?
      end

      def allow_all?
        @default == :allow
      end

      private

      def add_inet(address, ports)
        @inet << Rule.new(address, normalize_ports(ports))
      end

      def normalize_ports(ports)
        return if ports.nil?

        ports = [ports] unless ports.is_a?(Array)
        ports.each do |port|
          next if port.is_a?(Range) && port.begin.is_a?(Integer) && port.end.is_a?(Integer) && port.begin.between?(1, port.end) && port.end <= 65_535
          next if port.is_a?(Integer) && (1..65_535).cover?(port)

          raise ConfigurationError, "ports must contain integers or ranges between 1 and 65535"
        end.freeze
      end
    end
  end
end
