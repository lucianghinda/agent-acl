# frozen_string_literal: true

require "test_helper"
require "bundler"
require "open3"
require "rbconfig"

class DocumentationTaskTest < Minitest::Test
  def test_yard_task_replaces_stale_output_and_excludes_internal_docs
    with_project_copy do |root|
      doc_directory = File.join(root, "doc")
      FileUtils.mkdir_p(File.join(doc_directory, "docs", "internal"))
      File.write(File.join(doc_directory, "stale.md"), "stale")
      File.write(File.join(doc_directory, "docs", "internal", "plan.md"), "plan")

      stdout, stderr, status = Bundler.with_unbundled_env do
        Open3.capture3(RbConfig.ruby, "-S", "bundle", "exec", "rake", "yard", chdir: root)
      end

      assert status.success?, stderr
      assert_empty stderr
      refute_includes stdout, "[warn]"
      assert File.exist?(File.join(doc_directory, "AgentAcl.md"))
      assert File.exist?(File.join(doc_directory, "AgentAcl", "CLI.md"))
      assert File.exist?(File.join(doc_directory, "AgentAcl", "Manifest.md"))
      refute File.exist?(File.join(doc_directory, "stale.md"))
      refute File.exist?(File.join(doc_directory, "docs"))
    end
  end

  private

  def project_root
    File.expand_path("..", __dir__)
  end

  def with_project_copy
    Dir.mktmpdir do |root|
      %w[
        .rubocop.yml
        .yardopts
        CHANGELOG.md
        Gemfile
        Gemfile.lock
        README.md
        Rakefile
        agent-acl.gemspec
        docs
        exe
        lib
      ].each do |entry|
        source = File.join(project_root, entry)
        FileUtils.cp_r(source, File.join(root, entry)) if File.exist?(source)
      end

      yield root
    end
  end
end
