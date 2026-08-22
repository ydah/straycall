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

  it "serializes concurrent questions" do
    active = 0
    maximum = 0
    lock = Mutex.new
    io = instance_double(IO, flush: nil, gets: "yes\n")
    allow(io).to receive(:print) do
      lock.synchronize { maximum = [maximum, active += 1].max }
      sleep(0.01)
      lock.synchronize { active -= 1 }
    end
    prompt = described_class.new(io)

    2.times.map { Thread.new { prompt.allow?(:connect, "127.0.0.1:9") } }.each(&:join)

    expect(maximum).to eq(1)
  end
end
