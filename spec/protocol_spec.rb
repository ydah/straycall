# frozen_string_literal: true

require "straycall/reporter/protocol"

RSpec.describe Straycall::Reporter::Protocol do
  it "round trips backtraces and examples" do
    expect(described_class.parse(described_class.backtrace_response(12, ["example.rb:3"])))
      .to eq([:backtrace, 12, ["example.rb:3"]])
    expect(described_class.parse(described_class.example(file: "spec/a_spec.rb", line: 3)))
      .to eq([:example, {file: "spec/a_spec.rb", line: 3}])
  end
end
