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

  it "denies a disallowed destination hidden after an allowed sendmmsg entry" do
    request = request_for(Addrinfo.udp("192.0.2.1", 53), syscall: :sendmmsg, args: [5, 100, 2, 0])
    allow(request).to receive(:read).and_return(
      [1, 16].pack("Q<L<"),
      [2, 16].pack("Q<L<")
    )
    allow(request).to receive(:read_sockaddr).with(1, 16).and_return(Addrinfo.udp("127.0.0.1", 53))
    allow(request).to receive(:read_sockaddr).with(2, 16).and_return(Addrinfo.udp("192.0.2.1", 53))
    config.allow_loopback

    supervisor.send(:handle_sendmmsg, request)

    expect(request).to have_received(:error!).with(Errno::EPERM)
    expect(supervisor.violations.first.target).to include(host: "192.0.2.1", port: 53)
  end

  it "records every sendmmsg destination before continuing it" do
    config.on_violation = :record
    request = request_for(nil, syscall: :sendmmsg, args: [5, 100, 2, 0])
    allow(request).to receive(:read).and_return([1, 16].pack("Q<L<"), [2, 16].pack("Q<L<"))
    allow(request).to receive(:read_sockaddr).with(1, 16).and_return(Addrinfo.udp("192.0.2.1", 53))
    allow(request).to receive(:read_sockaddr).with(2, 16).and_return(Addrinfo.udp("198.51.100.1", 443))

    supervisor.send(:handle_sendmmsg, request)

    expect(request).to have_received(:continue!).with(unsafe: true).once
    expect(supervisor.violations.map { |violation| violation.target[:host] }).to eq(%w[192.0.2.1 198.51.100.1])
  end

  it "denies a sendmmsg batch when any prompted destination is rejected" do
    config.on_violation = :prompt
    prompt = instance_double(Straycall::Prompt)
    allow(prompt).to receive(:allow?).and_return(true, false)
    guarded = described_class.new(config, console: Straycall::Report::Console.new(output), prompt:)
    request = request_for(nil, syscall: :sendmmsg, args: [5, 100, 2, 0])
    allow(request).to receive(:read).and_return([1, 16].pack("Q<L<"), [2, 16].pack("Q<L<"))
    allow(request).to receive(:read_sockaddr).with(1, 16).and_return(Addrinfo.udp("192.0.2.1", 53))
    allow(request).to receive(:read_sockaddr).with(2, 16).and_return(Addrinfo.udp("198.51.100.1", 443))

    guarded.send(:handle_sendmmsg, request)

    expect(request).to have_received(:error!).with(Errno::EPERM).once
    expect(guarded.violations.map(&:action)).to eq(%i[allowed denied])
  end

  it "denies socket families without endpoint policy support" do
    unsupported_domain = 999
    request = request_for(nil, syscall: :socket, args: [unsupported_domain, Socket::SOCK_RAW, 0])

    supervisor.send(:handle_socket, request)

    expect(request).to have_received(:error!).with(Errno::EPERM)
    expect(supervisor.violations.first.target).to include(type: "socket", domain: unsupported_domain)
  end

  it "describes unsupported socket families in prompts" do
    config.on_violation = :prompt
    prompt = instance_double(Straycall::Prompt, allow?: false)
    guarded = described_class.new(config, console: Straycall::Report::Console.new(output), prompt:)
    request = request_for(nil, syscall: :socket, args: [999, Socket::SOCK_RAW, 0])

    guarded.send(:handle_socket, request)

    expect(prompt).to have_received(:allow?).with(:socket, "socket domain 999")
  end

  it "denies listen without a previously allowed bind" do
    request = request_for(nil, syscall: :listen, args: [5, 1])

    supervisor.send(:handle_listen, request)

    expect(request).to have_received(:error!).with(Errno::EPERM)
    expect(supervisor.violations.first.target).to include(type: "socket", operation: "listen")
  end

  it "allows listen after an allowed bind on the same socket" do
    config.allow_loopback
    request = request_for(nil, syscall: :listen, args: [5, 1])
    allow(File).to receive(:readlink).with("/proc/123/fd/5").and_return("socket:[42]")
    supervisor.instance_variable_get(:@bound_sockets)["42"] = Addrinfo.tcp("127.0.0.1", 4567)

    supervisor.send(:handle_listen, request)

    expect(request).to have_received(:continue!).with(no_args)
    expect(supervisor.violations).to be_empty
  end

  it "leaves unrecognized addresses to the kernel when all networking is allowed" do
    config.network.allow!
    request = request_for(nil, syscall: :connect, args: [5, 100, 16])

    supervisor.send(:handle_address, request, 1, 2)

    expect(request).to have_received(:continue!).with(no_args)
    expect(request).not_to have_received(:read_sockaddr)
    expect(supervisor.violations).to be_empty
  end

  it "continues a connected sendto that omits its already-checked destination" do
    request = request_for(nil, syscall: :sendto, args: [0, 1, 2, 3, 0, 0])

    supervisor.send(:handle_address, request, 4, 5)

    expect(request).to have_received(:continue!).with(no_args)
    expect(supervisor.violations).to be_empty
  end

  it "denies and reports a disallowed bind address" do
    request = request_for(Addrinfo.udp("0.0.0.0", 4567), syscall: :bind)

    supervisor.send(:handle_address, request, 1, 2)

    expect(request).to have_received(:error!).with(Errno::EPERM)
    expect(supervisor.violations.first.syscall).to eq(:bind)
    expect(supervisor.violations.first.suggestion).to eq('allow_host "0.0.0.0", ports: [4567]')
  end

  it "does not suggest an invalid port for an ephemeral bind" do
    request = request_for(Addrinfo.udp("0.0.0.0", 0), syscall: :bind)

    supervisor.send(:handle_address, request, 1, 2)

    expect(supervisor.violations.first.suggestion).to eq('allow_host "0.0.0.0"')
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

  it "reports an executable whose relative path cannot be resolved" do
    config.deny_exec_elsewhere!
    allow(config.filesystem).to receive(:resolve).and_raise(Straycall::PathResolutionError)
    request = instance_double(
      "Seccomp::Notify::Request",
      args: [1],
      syscall: :execve,
      tid: 123,
      instruction_pointer: 0,
      read_string: "tool",
      error!: nil,
      continue!: nil
    )

    supervisor.send(:handle_exec, request, nil, 0)

    expect(request).to have_received(:error!).with(Errno::EPERM)
    expect(supervisor.violations.first.target).to eq(type: "exec", path: "?")
  end

  it "resolves an execveat empty path through its file descriptor" do
    config.deny_exec_elsewhere!
    allow(File).to receive(:readlink).with("/proc/123/fd/5").and_return("/usr/bin/true")
    request = instance_double(
      "Seccomp::Notify::Request",
      args: [5, 100],
      syscall: :execveat,
      tid: 123,
      instruction_pointer: 0,
      read: "\0",
      read_string: nil,
      error!: nil,
      continue!: nil
    )

    supervisor.send(:handle_exec, request, 0, 1)

    expect(request).not_to have_received(:read_string)
    expect(request).to have_received(:error!).with(Errno::EPERM)
    expect(supervisor.violations.first.target).to eq(type: "exec", path: "/usr/bin/true")
  end

  def request_for(address, syscall: :connect, args: [0, 1, 2, 3, 4, 5])
    instance_double(
      "Seccomp::Notify::Request",
      args:,
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
