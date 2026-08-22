# frozen_string_literal: true

RSpec.describe Straycall do
  it "has a version number" do
    expect(Straycall::VERSION).not_to be nil
  end

  it "is a no-op when explicitly disabled" do
    previous = ENV["STRAYCALL"]
    ENV["STRAYCALL"] = "0"
    expect(described_class.available?).to be(false)
  ensure
    ENV["STRAYCALL"] = previous
  end

  it "loads and configures on unsupported platforms" do
    described_class.configure { |config| config.allow_loopback(ports: [5432]) }
    expect(described_class.config.network.allowed?(Addrinfo.tcp("127.0.0.1", 5432))).to be(true)
  end
end
