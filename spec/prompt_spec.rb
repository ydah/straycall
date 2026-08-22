# frozen_string_literal: true

require "straycall/prompt"

RSpec.describe Straycall::Prompt do
  it "accepts only an explicit yes" do
    io = instance_double(IO, print: nil, flush: nil, gets: "yes\n")

    expect(described_class.new(io).allow?(:connect, "192.0.2.1:443")).to be(true)
  end

  it "denies on an unavailable tty" do
    allow(File).to receive(:open).and_raise(Errno::ENXIO)

    expect(described_class.new.allow?(:connect, "192.0.2.1:443")).to be(false)
  end
end
