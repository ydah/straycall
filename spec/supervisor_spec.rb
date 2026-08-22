# frozen_string_literal: true

require "stringio"
require "straycall/supervisor"

RSpec.describe Straycall::Supervisor do
  let(:config) { Straycall::Config.new }
  let(:output) { StringIO.new }
  let(:supervisor) { described_class.new(config, console: Straycall::Report::Console.new(output)) }

  it "denies and reports a disallowed destination" do
    request = request_for(Addrinfo.tcp("192.0.2.1", 443))

    supervisor.send(:handle_address, request, 1, 2)

    expect(request).to have_received(:error!).with(Errno::EPERM)
    expect(supervisor.violations.first.target).to eq(type: "inet", host: "192.0.2.1", port: 443)
    expect(output.string).to include("connect(2) → 192.0.2.1:443")
  end

  it "continues an allowed destination" do
    config.allow_loopback(ports: [5432])
    request = request_for(Addrinfo.tcp("127.0.0.1", 5432))

    supervisor.send(:handle_address, request, 1, 2)

    expect(request).to have_received(:continue!).with(unsafe: true)
    expect(supervisor.violations).to be_empty
  end

  def request_for(address)
    instance_double(
      "Seccomp::Notify::Request",
      args: [0, 1, 2, 3, 4, 5],
      syscall: :connect,
      tid: 123,
      valid?: true,
      read_sockaddr: address,
      error!: nil,
      continue!: nil
    )
  end
end
