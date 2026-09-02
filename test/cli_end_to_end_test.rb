# frozen_string_literal: true

require "test_helper"
require "json"

class CliEndToEndTest < Minitest::Test
  def test_block_and_allow_wire_every_layer_on_macos
    skip "macOS only" unless RUBY_PLATFORM.include?("darwin")

    Dir.mktmpdir do |root|
      path = File.join(root, "tool")
      File.write(path, "#!/usr/bin/env ruby\nputs 'ok'\n")
      File.chmod(0o755, path)

      begin
        block_out = StringIO.new
        block_err = StringIO.new
        status = AgentAcl::CLI.new(root:, out: block_out, err: block_err).run(%w[block edit tool])

        assert_equal 0, status, block_err.string
        assert AgentAcl::Manifest.load(root).protected?(path)
        assert_raises(SystemCallError) { File.write(path, "changed") }
        assert_equal "#!/usr/bin/env ruby\nputs 'ok'\n", File.read(path)
        managed_files(root).each { assert File.file?(_1), "expected #{_1} to exist" }

        claude = JSON.parse(File.read(File.join(root, ".claude", "settings.json")))
        codex = JSON.parse(File.read(File.join(root, ".codex", "hooks.json")))
        opencode = JSON.parse(File.read(File.join(root, "opencode.json")))
        assert_includes claude.dig("permissions", "deny"), "Edit(tool)"
        assert(claude.dig("hooks", "PreToolUse").any? { _1["matcher"].include?("Edit") })
        assert(codex.dig("hooks", "PreToolUse").any? { _1["matcher"].include?("apply_patch") })
        assert_equal "deny", opencode.dig("permission", "edit", "tool")

        repair_out = StringIO.new
        repair_err = StringIO.new
        status = AgentAcl::CLI.new(root:, out: repair_out, err: repair_err).run(%w[block edit tool])
        assert_equal 0, status, repair_err.string
        assert_includes repair_out.string, "already protected, re-applied"

        allow_out = StringIO.new
        allow_err = StringIO.new
        status = AgentAcl::CLI.new(root:, out: allow_out, err: allow_err).run(%w[allow edit tool])

        assert_equal 0, status, allow_err.string
        assert_empty AgentAcl::Manifest.load(root).entries
        assert_equal 0o755, File.stat(path).mode & 0o7777
        File.write(path, "editable")
        refute JSON.parse(File.read(File.join(root, ".claude", "settings.json"))).dig("hooks", "PreToolUse")
        refute JSON.parse(File.read(File.join(root, ".codex", "hooks.json"))).dig("hooks", "PreToolUse")
        refute File.exist?(File.join(root, ".opencode", "plugin", "agent-acl.js"))
      ensure
        system("chflags", "nouchg", path, out: File::NULL, err: File::NULL) if File.exist?(path)
        File.chmod(0o755, path) if File.exist?(path)
      end
    end
  end

  def test_allow_unprotected_does_not_create_agent_configuration
    Dir.mktmpdir do |root|
      File.write(File.join(root, "LICENSE"), "license")

      status = AgentAcl::CLI.new(root:, out: StringIO.new, err: StringIO.new).run(%w[allow edit LICENSE])

      assert_equal 0, status
      refute File.exist?(File.join(root, ".agent-acl"))
      refute File.exist?(File.join(root, ".claude"))
      refute File.exist?(File.join(root, ".codex"))
      refute File.exist?(File.join(root, ".opencode"))
      refute File.exist?(File.join(root, "opencode.json"))
    end
  end

  private

  def managed_files(root)
    %w[
      .agent-acl
      .agent-acl.d/guard.rb
      .claude/settings.json
      .codex/hooks.json
      opencode.json
      .opencode/plugin/agent-acl.js
    ].map { File.join(root, _1) }
  end
end
