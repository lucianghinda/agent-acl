# frozen_string_literal: true

require "json"
require "open3"
require "rbconfig"
require "tmpdir"
require "fileutils"
require "test_helper"

GUARD_TEMPLATE_PATH = File.expand_path("../lib/agent_acl/templates/guard.rb", __dir__)
require GUARD_TEMPLATE_PATH if File.exist?(GUARD_TEMPLATE_PATH)

class GuardTest < Minitest::Test
  DENY_SENTENCE = "The user is not allowing changes to this file."

  def setup
    @root = Dir.mktmpdir("agent-acl-guard-test")
  end

  def teardown
    FileUtils.remove_entry(@root)
  end

  def test_denies_edit_on_a_protected_path
    write_manifest("LICENSE")

    result = run_guard(
      "tool_name" => "Edit",
      "tool_input" => { "file_path" => File.join(@root, "LICENSE") }
    )

    assert_equal 0, result.exitstatus
    assert_equal "deny", result.decision
    assert_includes result.reason, DENY_SENTENCE
    assert_includes result.reason, "agent-acl allow edit LICENSE"
  end

  def test_passes_edit_on_an_unprotected_path
    write_manifest("LICENSE")

    result = run_guard(
      "tool_name" => "Edit",
      "tool_input" => { "file_path" => File.join(@root, "README.md") }
    )

    assert_equal 0, result.exitstatus
    assert_equal "", result.stdout
  end

  def test_denies_apply_patch_that_targets_a_protected_path
    write_manifest("notes.txt")

    result = run_guard(
      "tool_name" => "apply_patch",
      "tool_input" => {
        "command" => <<~PATCH
          *** Begin Patch
          *** Update File: notes.txt
          @@
          -old
          +new
          *** End Patch
        PATCH
      }
    )

    assert_equal 0, result.exitstatus
    assert_equal "deny", result.decision
    assert_includes result.reason, DENY_SENTENCE
  end

  def test_passes_apply_patch_when_only_unprotected_paths_are_touched
    write_manifest("LICENSE")

    result = run_guard(
      "tool_name" => "apply_patch",
      "tool_input" => {
        "input" => <<~PATCH
          *** Begin Patch
          *** Update File: README.md
          @@
          -old
          +new
          *** End Patch
        PATCH
      }
    )

    assert_equal 0, result.exitstatus
    assert_equal "", result.stdout
  end

  def test_allows_read_only_shell_commands_on_a_protected_path
    write_manifest("LICENSE")

    [
      "cat LICENSE | grep MIT",
      "git diff -- LICENSE",
      "less LICENSE"
    ].each do |command|
      result = run_guard(
        "tool_name" => "Bash",
        "tool_input" => { "command" => command }
      )

      assert_equal 0, result.exitstatus, command
      assert_equal "", result.stdout, command
    end
  end

  def test_denies_write_options_on_otherwise_read_only_commands
    write_manifest("secret")

    [
      "git diff --output=secret",
      "git diff --output secret",
      "git show --ext-diff secret",
      "git log --textconv -- secret",
      "less -O secret README.md",
      "less --log-file=secret README.md"
    ].each do |command|
      result = run_guard(
        "tool_name" => "Bash",
        "tool_input" => { "command" => command }
      )

      assert_equal 0, result.exitstatus, command
      refute_empty result.stdout, command
      assert_equal "deny", result.decision, command
    end
  end

  def test_denies_ansi_c_quoted_shell_mutations
    write_manifest("secret")

    [
      %q(chmod u+w $'\x73ecret'),
      %q(chflags nouchg $'\x73ecret')
    ].each do |command|
      result = run_guard(
        "tool_name" => "Bash",
        "tool_input" => { "command" => command }
      )

      assert_equal 0, result.exitstatus, command
      refute_empty result.stdout, command
      assert_equal "deny", result.decision, command
    end
  end

  def test_denies_shell_writes_and_unlock_attempts
    write_manifest("LICENSE")

    [
      "sed -i '' 's/MIT/Apache/' LICENSE",
      "mv LICENSE LICENSE.bak",
      "cat README.md > LICENSE",
      "chmod u+w LICENSE",
      "chflags nouchg LICENSE",
      "chattr -i LICENSE",
      "agent-acl allow edit LICENSE"
    ].each do |command|
      result = run_guard(
        "tool_name" => "Bash",
        "tool_input" => { "command" => command }
      )

      assert_equal 0, result.exitstatus, command
      refute_empty result.stdout, command
      assert_equal "deny", result.decision, command
      assert_includes result.reason, DENY_SENTENCE, command
    end
  end

  def test_denies_all_supported_apply_patch_target_headers
    write_manifest("protected.txt")
    patches = [
      "*** Delete File: protected.txt\n",
      "*** Add File: protected.txt\n",
      "*** Update File: old.txt\n*** Move to: protected.txt\n"
    ]

    patches.each do |patch|
      result = run_guard(
        "tool_name" => "apply_patch",
        "tool_input" => { "command" => patch }
      )

      assert_equal 0, result.exitstatus, patch
      assert_equal "deny", result.decision, patch
      assert_includes result.reason, DENY_SENTENCE, patch
    end
  end

  def test_denies_shell_execution_hidden_inside_a_read_only_command
    write_manifest("LICENSE")

    [
      "cat LICENSE $(rm LICENSE)",
      "cat LICENSE `rm LICENSE`",
      "cat LICENSE & rm LICENSE",
      "cat LICENSE < <(rm LICENSE)"
    ].each do |command|
      result = run_guard(
        "tool_name" => "Bash",
        "tool_input" => { "command" => command }
      )

      assert_equal 0, result.exitstatus, command
      refute_empty result.stdout, command
      assert_equal "deny", result.decision, command
      assert_includes result.reason, DENY_SENTENCE, command
    end
  end

  def test_denies_interpreters_and_unknown_effect_commands_without_a_literal_path
    write_manifest("dir/LICENSE")

    [
      %(ruby -e 'File.delete(File.join("dir", "LICENSE"))'),
      "bundle exec rake test",
      %q{sed -n 'e ruby -e "File.delete(File.join(\"dir\",\"LICENSE\"))"' harmless.txt}
    ].each do |command|
      result = run_guard(
        "tool_name" => "Bash",
        "tool_input" => { "command" => command }
      )

      assert_equal 0, result.exitstatus, command
      refute_empty result.stdout, command
      assert_equal "deny", result.decision, command
      assert_includes result.reason, DENY_SENTENCE, command
    end
  end

  def test_resolves_escaped_globbed_nested_and_variable_shell_paths
    write_manifest("dir/LICENSE", "my notes.md")

    [
      "cd dir; rm LICENSE",
      "rm dir/LICEN?E",
      "rm my\\ notes.md",
      'p=dir/LICENSE; rm "$p"',
      "rm -rf dir",
      "find dir -delete",
      "git checkout -- .",
      "git restore .",
      "git clean -fd",
      "git add README.md"
    ].each do |command|
      result = run_guard(
        "tool_name" => "Bash",
        "tool_input" => { "command" => command }
      )

      assert_equal 0, result.exitstatus, command
      refute_empty result.stdout, command
      assert_equal "deny", result.decision, command
      assert_includes result.reason, DENY_SENTENCE, command
    end
  end

  def test_ignores_unrelated_tools
    write_manifest("LICENSE")

    result = run_guard(
      "tool_name" => "Grep",
      "tool_input" => { "pattern" => "license" }
    )

    assert_equal 0, result.exitstatus
    assert_equal "", result.stdout
  end

  def test_paths_with_spaces_are_parsed_from_the_manifest
    write_manifest("my notes.md")

    result = run_guard(
      "tool_name" => "Edit",
      "tool_input" => { "file_path" => File.join(@root, "my notes.md") }
    )

    assert_equal 0, result.exitstatus
    assert_equal "deny", result.decision
  end

  def test_sibling_paths_are_not_overmatched
    write_manifest("LICENSE")

    edit_result = run_guard(
      "tool_name" => "Edit",
      "tool_input" => { "file_path" => File.join(@root, "LICENSE.md") }
    )
    shell_result = run_guard(
      "tool_name" => "Bash",
      "tool_input" => { "command" => "rm LICENSE.md" }
    )

    assert_equal 0, edit_result.exitstatus
    assert_equal "", edit_result.stdout
    assert_equal 0, shell_result.exitstatus
    assert_equal "", shell_result.stdout
  end

  def test_denies_file_tools_through_existing_filesystem_aliases
    write_manifest("secret")
    create_filesystem_aliases("secret")

    %w[secret-link secret-hardlink alias a=b].each do |path|
      result = run_guard(
        "tool_name" => "Edit",
        "tool_input" => { "file_path" => File.join(@root, path) }
      )

      assert_equal 0, result.exitstatus, path
      refute_empty result.stdout, path
      assert_equal "deny", result.decision, path
    end
  end

  def test_denies_shell_mutation_through_existing_filesystem_aliases
    write_manifest("secret")
    create_filesystem_aliases("secret")

    %w[secret-link secret-hardlink alias].each do |path|
      command = "chmod u+w #{path} && printf x > #{path}"
      result = run_guard(
        "tool_name" => "Bash",
        "tool_input" => { "command" => command }
      )

      assert_equal 0, result.exitstatus, command
      refute_empty result.stdout, command
      assert_equal "deny", result.decision, command
    end

    equals_result = run_guard(
      "tool_name" => "Bash",
      "tool_input" => { "command" => 'chmod u+w "a=b" && printf x > "a=b"' }
    )
    assert_equal 0, equals_result.exitstatus
    refute_empty equals_result.stdout
    assert_equal "deny", equals_result.decision

    %w[secret-* secret-[lh]*].each do |glob|
      glob_result = run_guard(
        "tool_name" => "Bash",
        "tool_input" => { "command" => "chmod u+w #{glob}" }
      )
      assert_equal "deny", glob_result.decision, glob
    end
  end

  def test_opencode_denies_file_and_shell_mutation_through_existing_filesystem_aliases
    write_manifest("secret")
    create_filesystem_aliases("secret")
    FileUtils.cp(File.expand_path("../lib/agent_acl/templates/opencode_plugin.js", __dir__),
                 File.join(@root, "agent-acl-plugin.mjs"))
    attempts = %w[secret-link secret-hardlink alias].flat_map do |path|
      [
        [{ "tool" => "edit" }, { "args" => { "filePath" => path } }],
        [
          { "tool" => "bash" },
          { "args" => { "command" => "chmod u+w #{path} && printf x > #{path}" } }
        ]
      ]
    end
    attempts << [{ "tool" => "bash" }, { "args" => { "command" => "chmod u+w secret-*" } }]
    attempts << [{ "tool" => "bash" }, { "args" => { "command" => "chmod u+w secret-[lh]*" } }]
    attempts << [
      { "tool" => "bash" },
      { "args" => { "command" => "chmod u+w sec[r]et && printf x > sec[r]et" } }
    ]
    attempts << [{ "tool" => "bash" }, { "args" => { "command" => 'chmod u+w sec"r"et' } }]
    attempts << [{ "tool" => "bash" }, { "args" => { "command" => "chmod u+w ~/secret" } }]
    attempts << [{ "tool" => "bash" }, { "args" => { "command" => "chmod u+w ~/secret-link" } }]
    attempts << [{ "tool" => "edit" }, { "args" => { "filePath" => "a=b" } }]
    attempts << [
      { "tool" => "bash" },
      { "args" => { "command" => 'chmod u+w "a=b" && printf x > "a=b"' } }
    ]
    script = <<~JAVASCRIPT
      import { AgentAclPlugin } from "./agent-acl-plugin.mjs"

      const plugin = await AgentAclPlugin({ worktree: process.cwd() })
      const attempts = #{JSON.generate(attempts)}
      for (const [input, output] of attempts) {
        try {
          await plugin["tool.execute.before"](input, output)
          console.log("ALLOWED")
        } catch (error) {
          console.log(error.message)
        }
      }
    JAVASCRIPT

    stdout, stderr, status = Open3.capture3(
      { "HOME" => @root }, "node", "--input-type=module", "--eval", script, chdir: @root
    )

    assert status.success?, stderr
    assert_equal 14, stdout.lines.length, stderr
    refute_includes stdout, "ALLOWED"
    stdout.each_line { assert_includes _1, DENY_SENTENCE }
  rescue Errno::ENOENT
    skip "Node.js is required to execute the generated OpenCode plugin regression"
  end

  def test_opencode_denies_shell_mutation_of_a_filename_with_an_escaped_quote
    write_manifest('sec"ret')
    FileUtils.cp(File.expand_path("../lib/agent_acl/templates/opencode_plugin.js", __dir__),
                 File.join(@root, "agent-acl-plugin.mjs"))
    command = 'chmod u+w sec\"ret && printf x > sec\"ret'
    script = <<~JAVASCRIPT
      import { AgentAclPlugin } from "./agent-acl-plugin.mjs"

      const plugin = await AgentAclPlugin({ worktree: process.cwd() })
      try {
        await plugin["tool.execute.before"](
          { tool: "bash" },
          { args: { command: #{JSON.generate(command)} } },
        )
      } catch (error) {
        console.log(error.message)
      }
    JAVASCRIPT

    stdout, stderr, status = Open3.capture3(
      "node", "--input-type=module", "--eval", script, chdir: @root
    )

    assert status.success?, stderr
    assert_includes stdout, DENY_SENTENCE
  rescue Errno::ENOENT
    skip "Node.js is required to execute the generated OpenCode plugin regression"
  end

  def test_opencode_denies_shell_commands_with_hidden_write_effects
    write_manifest("secret")
    FileUtils.cp(File.expand_path("../lib/agent_acl/templates/opencode_plugin.js", __dir__),
                 File.join(@root, "agent-acl-plugin.mjs"))
    commands = [
      %q{sed -n 'e ruby -e "File.delete(\"secret\")"' harmless.txt},
      %q(chmod u+w $'\x73ecret'),
      "git diff --output=secret",
      "git show --ext-diff secret",
      "less -O secret README.md"
    ]
    script = <<~JAVASCRIPT
      import { AgentAclPlugin } from "./agent-acl-plugin.mjs"

      const plugin = await AgentAclPlugin({ worktree: process.cwd() })
      const commands = #{JSON.generate(commands)}
      for (const command of commands) {
        try {
          await plugin["tool.execute.before"](
            { tool: "bash" },
            { args: { command } },
          )
          console.log("ALLOWED")
        } catch (error) {
          console.log(error.message)
        }
      }
    JAVASCRIPT

    stdout, stderr, status = Open3.capture3(
      "node", "--input-type=module", "--eval", script, chdir: @root
    )

    assert status.success?, stderr
    assert_equal commands.length, stdout.lines.length, stderr
    refute_includes stdout, "ALLOWED"
    stdout.each_line { assert_includes _1, DENY_SENTENCE }
  rescue Errno::ENOENT
    skip "Node.js is required to execute the generated OpenCode plugin regression"
  end

  def test_denies_edits_to_agent_acl_infrastructure_when_any_path_is_protected
    write_manifest("LICENSE")

    result = run_guard(
      "tool_name" => "Write",
      "tool_input" => { "file_path" => File.join(@root, ".agent-acl") }
    )

    assert_equal 0, result.exitstatus
    assert_equal "deny", result.decision
    assert_includes result.reason, DENY_SENTENCE
  end

  def test_fails_closed_when_payload_json_is_malformed
    write_manifest("LICENSE")

    result = run_raw_guard("not json")

    assert_equal 0, result.exitstatus
    assert_equal "deny", result.decision
    assert_includes result.reason, DENY_SENTENCE
    assert_includes result.reason, "agent-acl guard error"
  end

  def test_fails_closed_when_payload_json_is_not_an_object
    write_manifest("LICENSE")

    result = run_raw_guard(JSON.generate("not an object"))

    assert_equal 0, result.exitstatus
    assert_equal "deny", result.decision
    assert_includes result.reason, "agent-acl guard error"
  end

  def test_fails_closed_when_a_known_tool_has_an_unrecognized_shape
    write_manifest("LICENSE")

    result = run_guard("tool_name" => "Edit", "tool_input" => {})

    assert_equal 0, result.exitstatus
    assert_equal "deny", result.decision
    assert_includes result.reason, "agent-acl guard error"
  end

  def test_passes_guard_errors_when_nothing_is_protected
    result = run_raw_guard("not json")

    assert_equal 0, result.exitstatus
    assert_equal "", result.stdout
  end

  def test_fails_closed_when_a_nonempty_manifest_is_malformed
    File.write(File.join(@root, ".agent-acl"), "not a manifest entry\n")

    result = run_guard(
      "tool_name" => "Edit",
      "tool_input" => { "file_path" => File.join(@root, "README.md") }
    )

    assert_equal 0, result.exitstatus
    assert_equal "deny", result.decision
    assert_includes result.reason, DENY_SENTENCE
    assert_includes result.reason, "agent-acl guard error"
  end

  Result = Struct.new(:stdout, :stderr, :exitstatus, keyword_init: true) do
    def json
      JSON.parse(stdout)
    end

    def decision
      json.dig("hookSpecificOutput", "permissionDecision")
    end

    def reason
      json.dig("hookSpecificOutput", "permissionDecisionReason")
    end
  end

  private

  def run_guard(payload)
    run_raw_guard(JSON.generate(payload))
  end

  def run_raw_guard(stdin_data)
    assert File.exist?(GUARD_TEMPLATE_PATH), "expected guard template to exist at #{GUARD_TEMPLATE_PATH}"

    stdout, stderr, status = Open3.capture3(
      RbConfig.ruby,
      GUARD_TEMPLATE_PATH,
      stdin_data: stdin_data,
      chdir: @root
    )

    Result.new(stdout: stdout, stderr: stderr, exitstatus: status.exitstatus)
  end

  def write_manifest(*relative_paths)
    relative_paths.each do |relative_path|
      absolute_path = File.join(@root, relative_path)
      FileUtils.mkdir_p(File.dirname(absolute_path))
      File.write(absolute_path, "content")
    end

    lines = relative_paths.map do |relative_path|
      "edit\t0644\t#{relative_path}"
    end

    File.write(File.join(@root, ".agent-acl"), lines.join("\n"))
  end

  def create_filesystem_aliases(path)
    File.symlink(path, File.join(@root, "#{path}-link"))
    File.symlink(path, File.join(@root, "alias"))
    File.symlink(path, File.join(@root, "a=b"))
    File.link(File.join(@root, path), File.join(@root, "#{path}-hardlink"))
  end
end
