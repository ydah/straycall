# frozen_string_literal: true

RSpec.describe Straycall::Policy do
  it "rejects reporter syscalls from the notification set" do
    expect { described_class.validate_notified!(:connect, :write) }
      .to raise_error(Straycall::ConfigurationError, /write/)
  end
end
