# frozen_string_literal: true

require "straycall/reporter/protocol"

RSpec.describe Straycall::Reporter::Protocol do
  it "round trips backtraces and examples" do
    expect(described_class.parse(described_class.backtrace_response(12, ["example.rb:3"])))
      .to eq([:backtrace, 12, ["example.rb:3"]])
    expect(described_class.parse(described_class.example(file: "spec/a_spec.rb", line: 3)))
      .to eq([:example, {file: "spec/a_spec.rb", line: 3}])
  end

  it "reads multiple bounded protocol lines without IO#gets" do
    reader, writer = IO.pipe
    protocol_reader = described_class::Reader.new(reader)
    writer.write("OK\nVIOLATION\n")

    expect(protocol_reader.read(timeout: 0.1)).to eq("OK\n")
    expect(protocol_reader.read(timeout: 0.1)).to eq("VIOLATION\n")
  ensure
    reader&.close
    writer&.close
  end
end
