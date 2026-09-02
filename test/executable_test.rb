# frozen_string_literal: true

require "test_helper"
require "open3"
require "rbconfig"

class ExecutableTest < Minitest::Test
  def test_version_runs_through_the_source_executable
    stdout, stderr, status = run_executable("version")

    assert status.success?, stderr
    assert_equal "#{AgentAcl::VERSION}\n", stdout
    assert_equal "", stderr
  end

  def test_list_uses_the_current_directory_as_the_project_root
    Dir.mktmpdir do |root|
      File.write(File.join(root, ".agent-acl"), "edit\t0644\tmy notes.md\n")

      stdout, stderr, status = run_executable("list", chdir: root)

      assert status.success?, stderr
      assert_equal "edit blocked -> my notes.md\n", stdout
      assert_equal "", stderr
    end
  end

  private

  def run_executable(*, chdir: nil)
    options = chdir ? { chdir: } : {}
    Open3.capture3(RbConfig.ruby, "-rbundler/setup", executable, *, **options)
  end

  def executable
    File.expand_path("../exe/agent-acl", __dir__)
  end
end
