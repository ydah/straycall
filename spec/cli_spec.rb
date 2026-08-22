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
end
