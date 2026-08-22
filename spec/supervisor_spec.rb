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

  it "denies an unconnected sendmsg destination" do
    address = Addrinfo.udp("192.0.2.1", 53)
    request = request_for(address, syscall: :sendmsg)
    allow(request).to receive(:read).and_return([1, 16].pack("Q<L<") + "\0" * 4)

    supervisor.send(:handle_sendmsg, request)

    expect(request).to have_received(:error!).with(Errno::EPERM)
    expect(supervisor.violations.first.syscall).to eq(:sendmsg)
  end

  it "denies writes outside configured roots" do
    config.allow_write_under("/tmp/allowed")
    config.deny_write_elsewhere!
    request = instance_double(
      "Seccomp::Notify::Request",
      args: [Straycall::Policy::Filesystem::AT_FDCWD, 1, Fcntl::O_WRONLY],
      syscall: :openat,
      tid: 123,
      instruction_pointer: 0,
      read_string: "/tmp/outside",
      error!: nil,
      continue!: nil
    )

    supervisor.send(:handle_openat, request)

    expect(request).to have_received(:error!).with(Errno::EPERM)
    expect(supervisor.violations.first.target[:path]).to eq("/tmp/outside")
  end

  it "continues a prompted violation when approved" do
    config.on_violation = :prompt
    prompt = instance_double(Straycall::Prompt, allow?: true)
    guarded = described_class.new(config, console: Straycall::Report::Console.new(output), prompt:)
    request = request_for(Addrinfo.tcp("192.0.2.1", 443))

    guarded.send(:handle_address, request, 1, 2)

    expect(request).to have_received(:continue!).with(unsafe: true)
    expect(guarded.violations.first.action).to eq(:allowed)
  end

  it "denies an executable outside the allow list" do
    config.allow_exec("/usr/bin/git")
    config.deny_exec_elsewhere!
    request = instance_double(
      "Seccomp::Notify::Request",
      args: [1],
      syscall: :execve,
      tid: 123,
      instruction_pointer: 0,
      read_string: "/usr/bin/curl",
      error!: nil,
      continue!: nil
    )

    supervisor.send(:handle_exec, request, nil, 0)

    expect(request).to have_received(:error!).with(Errno::EPERM)
    expect(supervisor.violations.first.target).to eq(type: "exec", path: "/usr/bin/curl")
  end

  def request_for(address, syscall: :connect)
    instance_double(
      "Seccomp::Notify::Request",
      args: [0, 1, 2, 3, 4, 5],
      syscall:,
      tid: 123,
      instruction_pointer: 0,
      valid?: true,
      read_sockaddr: address,
      error!: nil,
      continue!: nil
    )
  end
end
