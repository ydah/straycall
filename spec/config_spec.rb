# frozen_string_literal: true

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

  it "resolves allowed hosts once" do
    allow(Addrinfo).to receive(:getaddrinfo).and_return([Addrinfo.tcp("192.0.2.1", 0)])

    config.allow_host("registry.example", ports: [443])

    expect(config.network.allowed?(Addrinfo.tcp("192.0.2.1", 443))).to be(true)
  end

  it "rejects invalid modes and ports" do
    expect { config.on_violation = :maybe }.to raise_error(Straycall::ConfigurationError)
    expect { config.allow_loopback(ports: [0]) }.to raise_error(Straycall::ConfigurationError)
  end
end
