# frozen_string_literal: true

require "test_helper"

class CiConfigurationTest < Minitest::Test
  def test_linux_immutable_job_installs_zeitwerk_before_running_the_raw_harness
    workflow = File.read(File.expand_path("../.github/workflows/main.yml", __dir__))
    install = workflow.index('gem install zeitwerk --version "~> 2.8" --no-document')
    harness = workflow.index("ruby test/linux/run.rb")

    refute_nil install, "expected the root CI environment to install Zeitwerk"
    refute_nil harness, "expected the Linux immutable harness to run"
    assert_operator install, :<, harness
  end
end
