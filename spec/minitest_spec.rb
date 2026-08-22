# frozen_string_literal: true

require "straycall/minitest"

RSpec.describe Straycall::Minitest do
  it "loads as a no-op when seccomp is unavailable" do
    expect(described_class).to respond_to(:install)
  end
end
