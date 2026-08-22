# frozen_string_literal: true

require "tmpdir"
require "straycall/report/json"

RSpec.describe Straycall::Report::JSON do
  it "writes the versioned report schema" do
    violation = Straycall::Violation.new(:connect, 12, {type: "inet", host: "192.0.2.1", port: 443},
      ["example.rb:3"], nil, :denied, "allow_host", nil)

    Dir.mktmpdir do |directory|
      path = File.join(directory, "report.json")
      described_class.new(path).write([violation])
      report = ::JSON.parse(File.read(path))

      expect(report["version"]).to eq(1)
      expect(report.dig("violations", 0, "target", "host")).to eq("192.0.2.1")
    end
  end
end
