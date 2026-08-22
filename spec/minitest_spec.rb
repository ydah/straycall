# frozen_string_literal: true

require "open3"
require "rbconfig"

RSpec.describe "Straycall::Minitest" do
  it "loads as a no-op when explicitly disabled" do
    output, status = Open3.capture2e(
      {"STRAYCALL" => "0"},
      RbConfig.ruby, "-I#{File.expand_path("../lib", __dir__)}", "-e",
      'require "straycall/minitest"; abort unless Straycall::Minitest.respond_to?(:install)'
    )

    expect(status).to be_success, output
  end
end
