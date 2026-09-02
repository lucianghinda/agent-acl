# frozen_string_literal: true

require "test_helper"

class LlmGeneratorTest < Minitest::Test
  SCRIPT = File.expand_path("../bin/generate_llm.rb", __dir__)

  def test_generates_sorted_links_for_documentation_and_repository_roots
    with_documentation_tree do |root, main_document|
      stdout = StringIO.new

      assert generator_class.new(root:, stdout:).call

      expected_main = <<~MARKDOWN
        # Module: AgentAcl

        API documentation.

        # Documentation

        - [AgentAcl/CLI.md](AgentAcl/CLI.md)
        - [AgentAcl/Manifest.md](AgentAcl/Manifest.md)
        - [AgentAcl/Nested/Guard.md](AgentAcl/Nested/Guard.md)
      MARKDOWN
      expected_llm = expected_main
                     .gsub("[AgentAcl/", "[doc/AgentAcl/")
                     .gsub("(AgentAcl/", "(doc/AgentAcl/")

      assert_equal expected_main, File.read(main_document)
      assert_equal expected_llm, File.read(File.join(root, "llm.txt"))
      assert_equal "Updated #{main_document} (3 links)\n", stdout.string
    end
  end

  def test_generation_is_idempotent
    with_documentation_tree do |root, main_document|
      generator = generator_class.new(root:, stdout: StringIO.new)

      assert generator.call
      first_main = File.read(main_document)
      first_llm = File.read(File.join(root, "llm.txt"))

      assert generator.call
      assert_equal first_main, File.read(main_document)
      assert_equal first_llm, File.read(File.join(root, "llm.txt"))
    end
  end

  def test_fails_when_main_document_is_missing
    Dir.mktmpdir do |root|
      stderr = StringIO.new

      refute generator_class.new(root:, stdout: StringIO.new, stderr:).call
      assert_match %r{Missing .*/doc/AgentAcl\.md}, stderr.string
      refute File.exist?(File.join(root, "llm.txt"))
    end
  end

  private

  def generator_class
    assert File.file?(SCRIPT), "expected #{SCRIPT} to exist"
    require SCRIPT
    LlmGenerator
  end

  def with_documentation_tree
    Dir.mktmpdir do |root|
      main_document = File.join(root, "doc", "AgentAcl.md")
      FileUtils.mkdir_p(File.join(root, "doc", "AgentAcl", "Nested"))
      FileUtils.mkdir_p(File.join(root, "doc", "docs", "internal"))
      File.write(main_document, <<~MARKDOWN)
        # Module: AgentAcl

        API documentation.

        # Documentation

        - [stale](stale.md)
      MARKDOWN
      File.write(File.join(root, "doc", "AgentAcl", "Manifest.md"), "Manifest")
      File.write(File.join(root, "doc", "AgentAcl", "CLI.md"), "CLI")
      File.write(File.join(root, "doc", "AgentAcl", "Nested", "Guard.md"), "Guard")
      File.write(File.join(root, "doc", "docs", "internal", "plan.md"), "Internal")

      yield root, main_document
    end
  end
end
