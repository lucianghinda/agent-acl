# frozen_string_literal: true

require "test_helper"
require "json"

require_relative "../lib/agent_acl/installers/claude_code"
require_relative "../lib/agent_acl/installers/codex"
require_relative "../lib/agent_acl/installers/opencode"

class InstallersTest < Minitest::Test
  Entry = Struct.new(:path, keyword_init: true)
  Manifest = Data.define(:root, :entries, :removed_entries)

  def test_claude_code_install_merges_foreign_content_and_is_idempotent
    in_project do |root|
      config_path = File.join(root, ".claude", "settings.json")
      write_json(config_path, {
                   "model" => "sonnet",
                   "permissions" => {
                     "allow" => ["Read(lib/**/*.rb)"],
                     "deny" => ["Read(secret.env)", "Edit(user-owned.txt)"]
                   },
                   "hooks" => {
                     "PreToolUse" => [hook_group("Bash", "echo foreign")],
                     "PostToolUse" => [hook_group("Write", "echo post")]
                   }
                 })

      installer = AgentAcl::Installers::ClaudeCode.new(
        root: root,
        manifest: manifest(root, "blocked.txt", "notes/my doc.md")
      )
      template = write_template(root, "guard-source.rb", "# guard\n")
      installer.define_singleton_method(:guard_template_path) { template }

      installer.install

      parsed = JSON.parse(File.read(config_path))
      assert_equal "sonnet", parsed["model"]
      assert_equal ["Read(lib/**/*.rb)"], parsed.dig("permissions", "allow")
      assert_equal ["Read(secret.env)", "Edit(user-owned.txt)"], parsed.dig("permissions", "deny").take(2)
      assert_equal expected_claude_deny_rules("blocked.txt", "notes/my doc.md"),
                   parsed.dig("permissions", "deny").drop(2)
      assert_equal [hook_group("Bash", "echo foreign"), expected_claude_hook],
                   parsed.dig("hooks", "PreToolUse")
      assert_equal [hook_group("Write", "echo post")], parsed.dig("hooks", "PostToolUse")
      assert_equal "# guard\n", File.read(File.join(root, ".agent-acl.d", "guard.rb"))

      first_write = File.read(config_path)
      installer.install

      assert_equal first_write, File.read(config_path)
    end
  end

  def test_claude_code_sync_removes_only_the_previous_managed_block
    in_project do |root|
      config_path = File.join(root, ".claude", "settings.json")
      write_json(config_path, {
                   "permissions" => {
                     "deny" => ["Read(secret.env)"]
                   },
                   "hooks" => {
                     "PreToolUse" => [hook_group("Bash", "echo foreign")]
                   }
                 })
      template = write_template(root, "guard-source.rb", "# guard\n")

      installer = AgentAcl::Installers::ClaudeCode.new(
        root: root,
        manifest: manifest(root, "blocked.txt", "stale.txt")
      )
      installer.define_singleton_method(:guard_template_path) { template }
      installer.install

      installer = AgentAcl::Installers::ClaudeCode.new(
        root: root,
        manifest: manifest(root, "blocked.txt", removed: ["stale.txt"])
      )
      installer.define_singleton_method(:guard_template_path) { template }
      installer.sync

      parsed = JSON.parse(File.read(config_path))
      assert_equal ["Read(secret.env)"], parsed.dig("permissions", "deny").take(1)
      assert_equal expected_claude_deny_rules("blocked.txt"),
                   parsed.dig("permissions", "deny").drop(1)
      assert_equal [hook_group("Bash", "echo foreign"), expected_claude_hook],
                   parsed.dig("hooks", "PreToolUse")
    end
  end

  def test_claude_code_sync_removes_its_hook_when_nothing_is_protected
    in_project do |root|
      config_path = File.join(root, ".claude", "settings.json")
      write_json(config_path, {
                   "permissions" => { "deny" => ["Read(secret.env)"] },
                   "hooks" => { "PreToolUse" => [hook_group("Bash", "echo foreign")] }
                 })
      template = write_template(root, "guard-source.rb", "# guard\n")
      installer = AgentAcl::Installers::ClaudeCode.new(root: root, manifest: manifest(root, "blocked.txt"))
      installer.define_singleton_method(:guard_template_path) { template }
      installer.install

      empty = AgentAcl::Installers::ClaudeCode.new(
        root: root,
        manifest: manifest(root, removed: ["blocked.txt"])
      )
      empty.define_singleton_method(:guard_template_path) { template }
      empty.sync

      parsed = JSON.parse(File.read(config_path))
      assert_equal ["Read(secret.env)"], parsed.dig("permissions", "deny")
      assert_equal [hook_group("Bash", "echo foreign")], parsed.dig("hooks", "PreToolUse")
    end
  end

  def test_codex_install_merges_foreign_hooks_and_sync_removes_only_the_managed_hook
    in_project do |root|
      config_path = File.join(root, ".codex", "hooks.json")
      write_json(config_path, {
                   "description" => "Workspace hooks",
                   "hooks" => {
                     "PreToolUse" => [hook_group("Bash", "echo foreign")],
                     "SessionStart" => [hook_group("startup", "echo startup")]
                   }
                 })

      template = write_template(root, "guard-source.rb", "# codex guard\n")
      installer = AgentAcl::Installers::Codex.new(root: root, manifest: manifest(root, "blocked.txt"))
      installer.define_singleton_method(:guard_template_path) { template }

      installer.install

      parsed = JSON.parse(File.read(config_path))
      assert_equal "Workspace hooks", parsed["description"]
      assert_equal [hook_group("Bash", "echo foreign"), expected_codex_hook],
                   parsed.dig("hooks", "PreToolUse")
      assert_equal [hook_group("startup", "echo startup")], parsed.dig("hooks", "SessionStart")
      assert_equal "# codex guard\n", File.read(File.join(root, ".agent-acl.d", "guard.rb"))

      first_write = File.read(config_path)
      installer.install

      assert_equal first_write, File.read(config_path)

      empty_installer = AgentAcl::Installers::Codex.new(root: root, manifest: manifest(root))
      empty_installer.define_singleton_method(:guard_template_path) { template }
      empty_installer.sync

      parsed = JSON.parse(File.read(config_path))
      assert_equal [hook_group("Bash", "echo foreign")], parsed.dig("hooks", "PreToolUse")
      assert_equal [hook_group("startup", "echo startup")], parsed.dig("hooks", "SessionStart")
    end
  end

  def test_opencode_install_merges_foreign_content_and_sync_removes_stale_paths
    in_project do |root|
      config_path = File.join(root, "opencode.json")
      write_json(config_path, {
                   "$schema" => "https://opencode.ai/config.json",
                   "model" => "gpt-5",
                   "permission" => {
                     "read" => {
                       ".env" => "deny"
                     },
                     "edit" => {
                       "vendor/**" => "ask",
                       "user-owned.txt" => "deny"
                     }
                   }
                 })

      installer = AgentAcl::Installers::Opencode.new(
        root: root,
        manifest: manifest(root, "blocked.txt", "stale.txt")
      )

      installer.install

      parsed = JSON.parse(File.read(config_path))
      assert_equal "https://opencode.ai/config.json", parsed["$schema"]
      assert_equal "gpt-5", parsed["model"]
      assert_equal({ ".env" => "deny" }, parsed.dig("permission", "read"))
      foreign_rules = { "vendor/**" => "ask", "user-owned.txt" => "deny" }
      assert_equal expected_opencode_edit_rules(foreign_rules, "blocked.txt", "stale.txt"),
                   parsed.dig("permission", "edit")
      assert_equal File.read(File.expand_path("../lib/agent_acl/templates/opencode_plugin.js", __dir__)),
                   File.read(File.join(root, ".opencode", "plugin", "agent-acl.js"))
      plugin = File.read(File.join(root, ".opencode", "plugin", "agent-acl.js"))
      assert_includes plugin, '"tool.execute.before": async'
      assert_includes plugin, 'case "patch":'
      assert_includes plugin, "UNSAFE_SHELL_SYNTAX"
      assert_includes plugin, "agent-acl guard error"

      first_write = File.read(config_path)
      installer.install

      assert_equal first_write, File.read(config_path)

      AgentAcl::Installers::Opencode.new(
        root: root,
        manifest: manifest(root, "blocked.txt", removed: ["stale.txt"])
      ).sync

      parsed = JSON.parse(File.read(config_path))
      assert_equal expected_opencode_edit_rules(foreign_rules, "blocked.txt"),
                   parsed.dig("permission", "edit")
    end
  end

  def test_opencode_sync_removes_its_plugin_when_nothing_is_protected
    in_project do |root|
      installer = AgentAcl::Installers::Opencode.new(root: root, manifest: manifest(root, "blocked.txt"))
      installer.install
      plugin_path = File.join(root, ".opencode", "plugin", "agent-acl.js")
      assert File.exist?(plugin_path)

      AgentAcl::Installers::Opencode.new(
        root: root,
        manifest: manifest(root, removed: ["blocked.txt"])
      ).sync

      refute File.exist?(plugin_path)
      assert_equal({}, JSON.parse(File.read(File.join(root, "opencode.json"))))
    end
  end

  def test_install_refuses_a_symlinked_config_without_touching_its_target
    in_project do |root|
      Dir.mktmpdir do |outside|
        target = File.join(outside, "settings.json")
        File.write(target, "{\"foreign\":true}\n")
        FileUtils.mkdir_p(File.join(root, ".claude"))
        File.symlink(target, File.join(root, ".claude", "settings.json"))

        error = assert_raises(AgentAcl::Error) do
          AgentAcl::Installers::ClaudeCode.new(root:, manifest: manifest(root, "blocked.txt")).install
        end

        assert_includes error.message, "symlink"
        assert_equal "{\"foreign\":true}\n", File.read(target)
        refute File.exist?(File.join(root, ".agent-acl.d", "guard.rb"))
      end
    end
  end

  def test_install_refuses_a_symlinked_config_directory
    in_project do |root|
      Dir.mktmpdir do |outside|
        FileUtils.mkdir_p(File.join(root, ".codex"))
        File.symlink(outside, File.join(root, ".codex", "redirect"))
        config_path = File.join(File.realpath(root), ".codex", "redirect", "hooks.json")
        installer = AgentAcl::Installers::Codex.new(root:, manifest: manifest(root, "blocked.txt"))
        installer.define_singleton_method(:config_path) { config_path }

        error = assert_raises(AgentAcl::Error) { installer.install }

        assert_includes error.message, "symlink"
        refute File.exist?(File.join(outside, "hooks.json"))
      end
    end
  end

  def test_sync_preserves_identical_claude_rules_and_hook_that_preceded_agent_acl
    in_project do |root|
      config_path = File.join(root, ".claude", "settings.json")
      write_json(config_path, {
                   "permissions" => { "deny" => ["Edit(blocked.txt)"] },
                   "hooks" => { "PreToolUse" => [expected_claude_hook] }
                 })
      installer = AgentAcl::Installers::ClaudeCode.new(root:, manifest: manifest(root, "blocked.txt"))

      installer.install
      AgentAcl::Installers::ClaudeCode.new(
        root:, manifest: manifest(root, removed: ["blocked.txt"])
      ).sync

      parsed = JSON.parse(File.read(config_path))
      assert_equal ["Edit(blocked.txt)"], parsed.dig("permissions", "deny")
      assert_equal [expected_claude_hook], parsed.dig("hooks", "PreToolUse")
    end
  end

  def test_sync_preserves_an_identical_codex_hook_that_preceded_agent_acl
    in_project do |root|
      config_path = File.join(root, ".codex", "hooks.json")
      write_json(config_path, { "hooks" => { "PreToolUse" => [expected_codex_hook] } })

      AgentAcl::Installers::Codex.new(root:, manifest: manifest(root, "blocked.txt")).install
      AgentAcl::Installers::Codex.new(root:, manifest: manifest(root)).sync

      parsed = JSON.parse(File.read(config_path))
      assert_equal [expected_codex_hook], parsed.dig("hooks", "PreToolUse")
    end
  end

  def test_sync_preserves_an_identical_opencode_rule_that_preceded_agent_acl
    in_project do |root|
      config_path = File.join(root, "opencode.json")
      write_json(config_path, { "permission" => { "edit" => { "blocked.txt" => "deny" } } })

      AgentAcl::Installers::Opencode.new(root:, manifest: manifest(root, "blocked.txt")).install
      AgentAcl::Installers::Opencode.new(
        root:, manifest: manifest(root, removed: ["blocked.txt"])
      ).sync

      parsed = JSON.parse(File.read(config_path))
      assert_equal({ "blocked.txt" => "deny" }, parsed.dig("permission", "edit"))
    end
  end

  def test_opencode_reblock_repairs_a_tampered_owned_rule
    in_project do |root|
      config_path = File.join(root, "opencode.json")
      installer = AgentAcl::Installers::Opencode.new(root:, manifest: manifest(root, "blocked.txt"))
      installer.install
      config = JSON.parse(File.read(config_path))
      config.fetch("permission").fetch("edit")["blocked.txt"] = "ask"
      write_json(config_path, config)

      installer.install

      assert_equal "deny", JSON.parse(File.read(config_path)).dig("permission", "edit", "blocked.txt")
    end
  end

  def test_state_failure_happens_before_agent_config_is_changed
    in_project do |root|
      config_path = File.join(root, ".claude", "settings.json")
      write_json(config_path, { "foreign" => true })
      original = File.read(config_path)
      installer = AgentAcl::Installers::ClaudeCode.new(root:, manifest: manifest(root, "blocked.txt"))
      installer.define_singleton_method(:write_installer_state) { |*| fail AgentAcl::Error, "state unavailable" }

      assert_raises(AgentAcl::Error) { installer.install }

      assert_equal original, File.read(config_path)
    end
  end

  private

  def manifest(root, *paths, removed: [])
    Manifest.new(
      root: root,
      entries: paths.map { Entry.new(path: _1) },
      removed_entries: removed.map { Entry.new(path: _1) }
    )
  end

  def hook_group(matcher, command)
    {
      "matcher" => matcher,
      "hooks" => [
        {
          "type" => "command",
          "command" => command
        }
      ]
    }
  end

  def expected_claude_hook
    hook_group("Edit|Write|NotebookEdit|Bash", "ruby .agent-acl.d/guard.rb")
  end

  def expected_codex_hook
    hook_group("apply_patch|Bash", "ruby .agent-acl.d/guard.rb")
  end

  def expected_claude_deny_rules(*paths)
    (paths + managed_infra_paths).map { "Edit(#{_1})" }
  end

  def expected_opencode_edit_rules(foreign_rules, *paths)
    foreign_rules.merge((paths + managed_infra_paths).to_h { [_1, "deny"] })
  end

  def managed_infra_paths
    [
      ".agent-acl",
      ".agent-acl.d/guard.rb",
      ".agent-acl.d/installers.json",
      ".claude/settings.json",
      ".codex/hooks.json",
      "opencode.json"
    ]
  end

  def write_json(path, object)
    FileUtils.mkdir_p(File.dirname(path))
    File.write(path, "#{JSON.pretty_generate(object)}\n")
  end

  def write_template(root, name, contents)
    path = File.join(root, name)
    File.write(path, contents)
    path
  end

  def in_project(&)
    Dir.mktmpdir(&)
  end
end
