# frozen_string_literal: true

RSpec.describe Straycall::Policy do
  it "only enables high-volume filesystem notifications when configured" do
    config = Straycall::Config.new
    expect(described_class.notification_names(config)).not_to include(:openat, :execve)

    config.deny_write_elsewhere!
    config.deny_exec_elsewhere!
    expect(described_class.notification_names(config)).to include(:openat, :execve)
  end


  it "skips network notifications when all networking is allowed" do
    config = Straycall::Config.new
    config.network.allow!

    expect(described_class.notification_names(config)).not_to include(:socket, :connect, :sendmsg)

    config.on_violation = :record
    expect(described_class.notification_names(config)).to include(:socket, :connect, :sendmsg)
  end

  it "includes legacy x86 filesystem entry points" do
    stub_const("RUBY_PLATFORM", "x86_64-linux")
    config = Straycall::Config.new
    config.deny_write_elsewhere!

    expect(described_class.notification_names(config)).to include(:open, :creat, :unlink, :rename, :mkdir, :rmdir, :symlink)
  end

  it "uses a conditional openat notification unless reads are denied" do
    skip "seccomp user notifications are unavailable" unless Straycall.available?

    config = Straycall::Config.new
    config.deny_write_elsewhere!
    policy = described_class.seccomp(config)

    expect(policy.notified?(:openat)).to be(false)
    expect(policy.conditional_notifications(:x86_64)).not_to be_empty

    config.deny_read("/secret")
    expect(described_class.seccomp(config).notified?(:openat)).to be(true)
  end

  it "only allows io_uring after an explicit opt-out" do
    skip "seccomp user notifications are unavailable" unless Straycall.available?

    config = Straycall::Config.new
    syscall = Seccomp::Notify::Syscalls.number(:io_uring_setup, :x86_64)
    expect(described_class.seccomp(config).decisions(:x86_64)).to have_key(syscall)

    config.allow_io_uring!
    expect(described_class.seccomp(config).decisions(:x86_64)).not_to have_key(syscall)
  end
end
