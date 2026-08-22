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
end
