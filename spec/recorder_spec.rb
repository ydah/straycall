# frozen_string_literal: true

require "tmpdir"
require "straycall/recorder"

RSpec.describe Straycall::Recorder do
  it "writes a reviewable policy from observed accesses" do
    violations = [
      Straycall::Violation.new(:connect, 1, {type: "inet", host: "192.0.2.1", port: 443}, nil, nil, :allowed, nil, nil),
      Straycall::Violation.new(:openat, 1, {type: "file", path: "/work/tmp/a"}, nil, nil, :allowed, nil, nil),
      Straycall::Violation.new(:execve, 1, {type: "exec", path: "/usr/bin/git"}, nil, nil, :allowed, nil, nil)
    ]

    Dir.mktmpdir do |directory|
      path = File.join(directory, "policy.yml")
      described_class.new(path).write(violations)
      policy = YAML.safe_load_file(path)

      expect(policy.dig("network", "allow", 0, "ports")).to eq([443])
      expect(policy.dig("write", "allow")).to eq(["/work/tmp"])
      expect(policy.dig("exec", "allow")).to eq(["/usr/bin/git"])
    end
  end

  it "does not turn unreadable targets into broad allow rules" do
    violations = [
      Straycall::Violation.new(:openat, 1, {type: "file", path: "?"}, nil, nil, :allowed, nil, nil),
      Straycall::Violation.new(:bind, 1, {type: "inet", host: "127.0.0.1", port: 0}, nil, nil, :allowed, nil, nil)
    ]

    Dir.mktmpdir do |directory|
      path = File.join(directory, "policy.yml")
      described_class.new(path).write(violations)
      policy = YAML.safe_load_file(path)

      expect(policy.dig("write", "allow")).to be_empty
      expect(policy.dig("network", "allow", 0)).to eq("host" => "127.0.0.1")
    end
  end
end
