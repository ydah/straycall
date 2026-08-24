# frozen_string_literal: true

require "tmpdir"

RSpec.describe Straycall::Policy::Exec do
  it "denies executables outside the allow list when enabled" do
    policy = described_class.new
    policy.allow("/usr/bin/git")
    policy.deny_elsewhere!

    expect(policy.allowed?("/usr/bin/git")).to be(true)
    expect(policy.allowed?("/usr/bin/curl")).to be(false)
  end

  it "matches executable aliases by their resolved path" do
    Dir.mktmpdir do |directory|
      executable = File.join(directory, "tool")
      alias_path = File.join(directory, "alias")
      File.write(executable, "")
      File.symlink(executable, alias_path)
      policy = described_class.new
      policy.deny(executable)

      expect(policy.allowed?(alias_path)).to be(false)
    end
  end
end
