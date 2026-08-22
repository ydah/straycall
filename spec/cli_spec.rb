# frozen_string_literal: true

require "straycall/cli"

RSpec.describe Straycall::CLI do
  before { Straycall.reset! }

  it "applies the bundle install preset" do
    cli = described_class.new(["--preset=bundle-install", "--", "true"])

    cli.send(:parse!)

    expect(Straycall.config.on_violation).to eq(:prompt)
    expect(Straycall.config.filesystem).to be_active
  end

  it "returns a usage error for an unreadable configuration" do
    cli = described_class.new(["--config", "/definitely/missing/straycall.yml", "--", "true"])

    expect { expect(cli.run).to eq(64) }.to output(/cannot read configuration/).to_stderr
  end

  it "returns the shell exit code for a child terminated by a signal" do
    status = instance_double(Process::Status, signaled?: true, termsig: Signal.list.fetch("KILL"))

    expect(described_class.new([]).send(:child_exit_code, status)).to eq(128 + Signal.list.fetch("KILL"))
  end
end
