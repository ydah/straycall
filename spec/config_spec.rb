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
    expect(config.network.allowed?(Addrinfo.unix("/tmp/postgresql.evil"))).to be(false)
    expect(config.network.allowed?(Addrinfo.unix("/var/run/postgres"))).to be(false)
    expect(config.network.allowed?(Addrinfo.unix("\0postgres"))).to be(false)
  end


  it "matches IPv4-mapped IPv6 addresses against IPv4 rules" do
    config.allow_loopback(ports: 1..65_535)

    expect(config.network.allowed?(Addrinfo.tcp("::ffff:127.0.0.1", 5432))).to be(true)
  end

  it "allows all address families when the network default is allow" do
    config.network.allow!

    expect(config.network.allowed?(Addrinfo.tcp("192.0.2.1", 443))).to be(true)
    expect(config.network.allowed?(Addrinfo.unix("/tmp/example.sock"))).to be(true)
  end

  it "allows configured socket domains and unbound listeners" do
    config.allow_socket_domain(17)
    config.allow_unbound_listen!

    expect(config.network.allowed_domain?(17)).to be(true)
    expect(config.network.allowed_domain?(16)).to be(false)
    expect(config.network.unbound_listen_allowed?).to be(true)
  end

  it "keeps io_uring disabled unless explicitly allowed" do
    expect(config.io_uring_allowed?).to be(false)

    config.allow_io_uring!

    expect(config.io_uring_allowed?).to be(true)
  end

  it "resolves allowed hosts once" do
    allow(Addrinfo).to receive(:getaddrinfo).and_return([Addrinfo.tcp("192.0.2.1", 0)])

    config.allow_host("registry.example", ports: [443])

    expect(config.network.allowed?(Addrinfo.tcp("192.0.2.1", 443))).to be(true)
  end

  it "rejects invalid modes and ports" do
    expect { config.on_violation = :maybe }.to raise_error(Straycall::ConfigurationError)
    expect { config.allow_loopback(ports: [0]) }.to raise_error(Straycall::ConfigurationError)
    expect { config.allow_loopback(ports: [10..1]) }.to raise_error(Straycall::ConfigurationError)
    expect { config.report_backtrace = "yes" }.to raise_error(Straycall::ConfigurationError)
    expect { config.report_path = "" }.to raise_error(Straycall::ConfigurationError)
  end

  it "rejects paths that could become accidental broad permissions" do
    expect { config.allow_write_under(nil) }.to raise_error(Straycall::ConfigurationError)
    expect { config.deny_read("") }.to raise_error(Straycall::ConfigurationError)
    expect { config.allow_unix("bad\0path") }.to raise_error(Straycall::ConfigurationError)
    expect { config.allow_host(nil) }.to raise_error(Straycall::ConfigurationError)
    expect { config.allow_exec("") }.to raise_error(Straycall::ConfigurationError)
    expect { config.deny_exec("bad\0path") }.to raise_error(Straycall::ConfigurationError)
    expect { config.report_path = "bad\0path" }.to raise_error(Straycall::ConfigurationError)
  end

  it "reports host resolution failures as configuration errors" do
    allow(Addrinfo).to receive(:getaddrinfo).and_raise(SocketError, "not found")

    expect { config.allow_host("missing.example") }.to raise_error(Straycall::ConfigurationError, /cannot resolve host/)
  end

  it "loads YAML policies" do
    allow(Addrinfo).to receive(:getaddrinfo).and_return([Addrinfo.tcp("192.0.2.1", 0)])
    yaml = <<~YAML
      network:
        default: deny
        allow:
          - host: registry.example
            ports: [443]
          - domain: 17
        allow_unbound_listen: true
      write:
        default: deny
        allow: [tmp]
        deny_read: [~/.ssh]
      exec:
        default: deny
        allow_under: [/usr/bin]
        deny: [/usr/bin/curl]
      on_violation: warn
      report_backtrace: false
    YAML

    Dir.mktmpdir do |directory|
      path = File.join(directory, "config.yml")
      File.write(path, yaml)
      loaded = described_class.load(path)

      expect(loaded.network.allowed?(Addrinfo.tcp("192.0.2.1", 443))).to be(true)
      expect(loaded.network.allowed_domain?(17)).to be(true)
      expect(loaded.network.unbound_listen_allowed?).to be(true)
      expect(loaded.filesystem).to be_active
      expect(loaded.exec.allowed?("/usr/bin/ruby")).to be(true)
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

  it "reports unreadable YAML files as configuration errors" do
    expect { described_class.load("/definitely/missing/straycall.yml") }
      .to raise_error(Straycall::ConfigurationError, /cannot read configuration/)
  end

  it "rejects false and null values instead of treating them as absent" do
    expect { config.apply("network" => false) }.to raise_error(Straycall::ConfigurationError, /network must be a mapping/)
    expect { config.apply("on_violation" => false) }.to raise_error(Straycall::ConfigurationError, /on_violation/)
    expect { config.apply("report_path" => nil) }.to raise_error(Straycall::ConfigurationError, /report_path/)
    expect { config.apply("write" => {"allow" => false}) }.to raise_error(Straycall::ConfigurationError, /array/)
  end

  it "rejects ambiguous network allow rules" do
    rule = {"host" => "127.0.0.1", "unix" => "/tmp/socket"}

    expect { config.apply("network" => {"allow" => [rule]}) }
      .to raise_error(Straycall::ConfigurationError, /exactly one/)
  end
end
