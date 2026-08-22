# frozen_string_literal: true

require "tmpdir"

RSpec.describe Straycall::Config do
  let(:config) { described_class.new }

  it "allows loopback ports for IPv4 and IPv6" do
    config.allow_loopback(ports: [5432, 6000..6002])

    expect(config.network.allowed?(Addrinfo.tcp("127.0.0.1", 5432))).to be(true)
    expect(config.network.allowed?(Addrinfo.tcp("::1", 6001))).to be(true)
    expect(config.network.allowed?(Addrinfo.tcp("127.0.0.1", 80))).to be(false)
  end

  it "allows Unix socket path prefixes" do
    config.allow_unix("/tmp/postgres")

    expect(config.network.allowed?(Addrinfo.unix("/tmp/postgres/.s.PGSQL.5432"))).to be(true)
    expect(config.network.allowed?(Addrinfo.unix("/var/run/postgres"))).to be(false)
  end

  it "allows all address families when the network default is allow" do
    config.network.allow!

    expect(config.network.allowed?(Addrinfo.tcp("192.0.2.1", 443))).to be(true)
    expect(config.network.allowed?(Addrinfo.unix("/tmp/example.sock"))).to be(true)
  end

  it "resolves allowed hosts once" do
    allow(Addrinfo).to receive(:getaddrinfo).and_return([Addrinfo.tcp("192.0.2.1", 0)])

    config.allow_host("registry.example", ports: [443])

    expect(config.network.allowed?(Addrinfo.tcp("192.0.2.1", 443))).to be(true)
  end

  it "rejects invalid modes and ports" do
    expect { config.on_violation = :maybe }.to raise_error(Straycall::ConfigurationError)
    expect { config.allow_loopback(ports: [0]) }.to raise_error(Straycall::ConfigurationError)
  end

  it "loads YAML policies" do
    allow(Addrinfo).to receive(:getaddrinfo).and_return([Addrinfo.tcp("192.0.2.1", 0)])
    yaml = <<~YAML
      network:
        default: deny
        allow:
          - host: registry.example
            ports: [443]
      write:
        default: deny
        allow: [tmp]
        deny_read: [~/.ssh]
      exec:
        default: allow
        deny: [/usr/bin/curl]
      on_violation: warn
      report_backtrace: false
    YAML

    Dir.mktmpdir do |directory|
      path = File.join(directory, "config.yml")
      File.write(path, yaml)
      loaded = described_class.load(path)

      expect(loaded.network.allowed?(Addrinfo.tcp("192.0.2.1", 443))).to be(true)
      expect(loaded.filesystem).to be_active
      expect(loaded.exec.allowed?("/usr/bin/curl")).to be(false)
      expect(loaded.on_violation).to eq(:warn)
      expect(loaded.report_backtrace).to be(false)
    end
  end

  it "rejects malformed YAML configuration" do
    Dir.mktmpdir do |directory|
      path = File.join(directory, "config.yml")
      File.write(path, "unknown: true\n")

      expect { described_class.load(path) }.to raise_error(Straycall::ConfigurationError, /unknown/)
    end
  end
end
