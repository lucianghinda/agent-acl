# frozen_string_literal: true

require "test_helper"

class PrepareReleaseTest < Minitest::Test
  SCRIPT = File.expand_path("../bin/prepare_release", __dir__)

  def test_runs_validation_documentation_generation_and_build_in_order
    events = []
    runner = lambda do |command, working_directory|
      events << [:command, command, working_directory]
      true
    end
    builder = lambda do |working_directory|
      events << [:build, working_directory]
      true
    end

    assert preparer_class.new(root:, ruby:, runner:, builder:).call
    assert_equal expected_commands.map { [:command, _1, root] } + [[:build, root]], events
  end

  def test_stops_after_the_first_failed_command
    calls = []
    stderr = StringIO.new
    runner = lambda do |command, working_directory|
      calls << [command, working_directory]
      command != expected_commands.fetch(1)
    end
    builder = ->(_working_directory) { flunk "builder should not run after a failed command" }

    refute preparer_class.new(root:, ruby:, runner:, builder:, stderr:).call
    assert_equal expected_commands.first(2).map { [_1, root] }, calls
    assert_equal "Release preparation failed: #{expected_commands.fetch(1).join(" ")}\n", stderr.string
  end

  def test_fails_when_gem_building_fails
    stderr = StringIO.new
    runner = ->(_command, _working_directory) { true }
    builder = ->(_working_directory) { false }

    refute preparer_class.new(root:, ruby:, runner:, builder:, stderr:).call
    assert_equal "Release preparation failed: build agent-acl.gemspec\n", stderr.string
  end

  def test_release_utilities_are_executable_ruby_scripts
    generate_llm = File.expand_path("../bin/generate_llm.rb", __dir__)

    assert File.executable?(SCRIPT), "expected #{SCRIPT} to be executable"
    assert File.executable?(generate_llm), "expected #{generate_llm} to be executable"
    assert_equal "#!/usr/bin/env ruby\n", File.open(SCRIPT, &:gets)
    assert_equal "#!/usr/bin/env ruby\n", File.open(generate_llm, &:gets)
  end

  private

  def preparer_class
    assert File.file?(SCRIPT), "expected #{SCRIPT} to exist"
    load SCRIPT unless defined?(ReleasePreparer)
    ReleasePreparer
  end

  def root
    "/project"
  end

  def ruby
    "/ruby"
  end

  def expected_commands
    [
      [ruby, "-S", "bundle", "exec", "rake"],
      [ruby, "-S", "bundle", "exec", "rake", "yard"],
      [ruby, File.join(root, "bin", "generate_llm.rb")]
    ]
  end
end
