# frozen_string_literal: true

RSpec.describe Straycall::Policy do
  it "rejects reporter syscalls from the notification set" do
    expect { described_class.validate_notified!(:connect, :write) }
      .to raise_error(Straycall::ConfigurationError, /write/)
  end

  it "only enables high-volume filesystem notifications when configured" do
    config = Straycall::Config.new
    expect(described_class.notification_names(config)).not_to include(:openat, :execve)

    config.deny_write_elsewhere!
    config.deny_exec_elsewhere!
    expect(described_class.notification_names(config)).to include(:openat, :execve)
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
end
