#!/usr/bin/env ruby
# frozen_string_literal: true

class LlmGenerator
  MAIN_DOCUMENT = File.join("doc", "AgentAcl.md")

  def initialize(root: File.expand_path("..", __dir__), stdout: $stdout, stderr: $stderr)
    @root = root
    @stdout = stdout
    @stderr = stderr
  end

  def call
    unless File.file?(main_document)
      stderr.puts "Missing #{main_document}"
      return false
    end

    content = File.read(main_document)
    content = content.sub(/(?:\A|\n)# Documentation[ \t]*\r?\n.*\z/m, "").rstrip
    content = [content, "# Documentation", documentation_links].join("\n\n").rstrip << "\n"

    File.write(main_document, content)
    File.write(llm_document, root_relative_links(content))
    stdout.puts "Updated #{main_document} (#{documentation_files.size} links)"
    true
  end

  private

  attr_reader :root, :stdout, :stderr

  def main_document
    @main_document ||= File.join(root, MAIN_DOCUMENT)
  end

  def llm_document
    File.join(root, "llm.txt")
  end

  def documentation_files
    @documentation_files ||= Dir.glob(File.join(root, "doc", "AgentAcl", "**", "*.md"))
  end

  def documentation_links
    documentation_files.map do |path|
      relative_path = path.delete_prefix("#{File.dirname(main_document)}/")
      "- [#{relative_path}](#{relative_path})"
    end.join("\n")
  end

  def root_relative_links(content)
    content
      .gsub("[AgentAcl/", "[doc/AgentAcl/")
      .gsub("(AgentAcl/", "(doc/AgentAcl/")
  end
end

exit(LlmGenerator.new.call ? 0 : 1) if $PROGRAM_NAME == __FILE__
