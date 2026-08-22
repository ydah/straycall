# frozen_string_literal: true

require "tmpdir"

RSpec.describe Straycall::Policy::Filesystem do
  it "allows only path-boundary matches without resolving symlinks" do
    Dir.mktmpdir do |directory|
      allowed = File.join(directory, "allowed")
      policy = described_class.new
      policy.allow_write_under(allowed)
      policy.deny_write_elsewhere!

      expect(policy.allowed_write?(File.join(allowed, "result.json"))).to be(true)
      expect(policy.allowed_write?("#{allowed}-other/result.json")).to be(false)
    end
  end

  it "recognizes write flags and sensitive read prefixes" do
    policy = described_class.new
    policy.deny_read("~/.ssh")

    expect(policy.write?(Fcntl::O_CREAT)).to be(true)
    expect(policy.write?(Fcntl::O_RDONLY)).to be(false)
    expect(policy.denied_read?(File.expand_path("~/.ssh/id_ed25519"))).to be(true)
  end

  it "resolves relative dirfd paths through proc without realpath" do
    policy = described_class.new
    allow(File).to receive(:readlink).with("/proc/42/fd/7").and_return("/work/project")

    expect(policy.resolve("tmp/../log/app.log", tid: 42, dirfd: 7)).to eq("/work/project/log/app.log")
  end

  it "fails closed when the target process path cannot be resolved" do
    policy = described_class.new
    allow(File).to receive(:readlink).and_raise(Errno::ENOENT)

    expect { policy.resolve("tmp/result", tid: 42) }.to raise_error(Straycall::PathResolutionError)
  end

  it "bounds its decision cache" do
    policy = described_class.new(cache_size: 2)
    3.times { |index| policy.allowed_write?("/tmp/#{index}") }

    expect(policy.instance_variable_get(:@cache).length).to eq(2)
  end

  it "allows the reporter to name its thread through proc" do
    policy = described_class.new
    policy.deny_write_elsewhere!

    expect(policy.allowed_write?("/proc/self/task/42/comm")).to be(true)
  end
end
