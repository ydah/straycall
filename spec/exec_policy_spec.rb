# frozen_string_literal: true

RSpec.describe Straycall::Policy::Exec do
  it "denies executables outside the allow list when enabled" do
    policy = described_class.new
    policy.allow("/usr/bin/git")
    policy.deny_elsewhere!

    expect(policy.allowed?("/usr/bin/git")).to be(true)
    expect(policy.allowed?("/usr/bin/curl")).to be(false)
  end
end
