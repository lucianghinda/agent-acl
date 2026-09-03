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
  UNANALYSABLE_SENTENCE = "agent-acl could not determine whether this command is safe."

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

  def test_allows_redirecting_a_protected_read_to_an_unprotected_path
    write_manifest("protected.txt")

    result = run_guard(
      "tool_name" => "Bash",
      "tool_input" => { "command" => "cat protected.txt > unprotected.txt" }
    )

    assert_equal 0, result.exitstatus
    assert_equal "", result.stdout
  end

  def test_allows_unknown_commands_that_do_not_reference_protected_paths
    write_manifest("protected.txt")

    ["date", "arbitrary-unlisted-executable --check README.md"].each do |command|
      result = run_guard(
        "tool_name" => "Bash",
        "tool_input" => { "command" => command }
      )

      assert_equal 0, result.exitstatus, command
      assert_equal "", result.stdout, command
    end
  end

  def test_allows_read_only_sed_on_an_unprotected_path
    write_manifest("protected.txt")

    result = run_guard(
      "tool_name" => "Bash",
      "tool_input" => { "command" => "sed -n '1,3p' Gemfile" }
    )

    assert_equal 0, result.exitstatus
    assert_equal "", result.stdout
  end

  def test_denies_mutating_sed_on_the_referenced_protected_path
    write_manifest("unrelated.txt", "protected.txt")

    result = run_guard(
      "tool_name" => "Bash",
      "tool_input" => { "command" => "sed -i '' 's/a/b/' protected.txt" }
    )

    assert_equal 0, result.exitstatus
    assert_equal "deny", result.decision
    assert_includes result.reason, DENY_SENTENCE
    refute_includes result.reason, UNANALYSABLE_SENTENCE
    assert_includes result.reason, "protected.txt"
    refute_includes result.reason, "unrelated.txt"
  end

  def test_allows_shell_operators_inside_quoted_arguments
    write_manifest("protected.txt")

    [
      %q(grep -n "a\|b" unprotected.txt),
      'grep -n "a;b" unprotected.txt',
      'grep -n "a&&b" unprotected.txt',
      'grep -n "a||b" unprotected.txt'
    ].each do |command|
      result = run_guard(
        "tool_name" => "Bash",
        "tool_input" => { "command" => command }
      )

      assert_equal 0, result.exitstatus, command
      assert_equal "", result.stdout, command
    end
  end

  def test_allows_inert_ambiguous_syntax_inside_single_quotes
    write_manifest("protected.txt")

    [
      "grep 'a&b' protected.txt",
      "grep 'a{2}' protected.txt",
      "grep '$(literal)' protected.txt",
      "grep '`literal`' protected.txt"
    ].each do |command|
      result = run_guard(
        "tool_name" => "Bash",
        "tool_input" => { "command" => command }
      )

      assert_equal 0, result.exitstatus, command
      assert_equal "", result.stdout, command
    end
  end

  def test_denies_command_substitution_inside_double_quotes_as_unanalysable
    write_manifest("protected.txt")

    result = run_guard(
      "tool_name" => "Bash",
      "tool_input" => { "command" => 'grep "$(printf pattern)" protected.txt' }
    )

    assert_equal 0, result.exitstatus
    assert_equal "deny", result.decision
    assert_includes result.reason, UNANALYSABLE_SENTENCE
    refute_includes result.reason, DENY_SENTENCE
  end

  def test_denies_complex_parameter_expansion_inside_double_quotes_as_unanalysable
    write_manifest("protected.txt")

    [
      'p=; rm "${p:-protected.txt}"',
      'p=unprotected; rm "${p:+protected.txt}"',
      'p=protected.txt; rm "${p%.*}.txt"'
    ].each do |command|
      result = run_guard(
        "tool_name" => "Bash",
        "tool_input" => { "command" => command }
      )

      assert_equal 0, result.exitstatus, command
      assert_equal "deny", result.decision, command
      assert_includes result.reason, UNANALYSABLE_SENTENCE, command
      refute_includes result.reason, DENY_SENTENCE, command
    end
  end

  def test_ignores_protected_paths_in_shell_comments
    write_manifest("protected.txt")

    [
      "rm unprotected.txt # protected.txt",
      "arbitrary README.md # protected.txt"
    ].each do |command|
      result = run_guard(
        "tool_name" => "Bash",
        "tool_input" => { "command" => command }
      )

      assert_equal 0, result.exitstatus, command
      assert_equal "", result.stdout, command
    end
  end

  def test_does_not_expand_shell_variables_inside_single_quotes
    write_manifest("protected.txt")

    [
      "cat '$MISSING'",
      "p=protected.txt; rm '$p'",
      "p='$MISSING'; echo ok"
    ].each do |command|
      result = run_guard(
        "tool_name" => "Bash",
        "tool_input" => { "command" => command }
      )

      assert_equal 0, result.exitstatus, command
      assert_equal "", result.stdout, command
    end
  end

  def test_unknown_command_denial_names_only_a_referenced_protected_path
    write_manifest("unrelated.txt", "protected-a.txt", "protected-b.txt")

    result = run_guard(
      "tool_name" => "Bash",
      "tool_input" => {
        "command" => "cat protected-a.txt; sed -n '1,5p' protected-b.txt"
      }
    )

    assert_equal 0, result.exitstatus
    assert_equal "deny", result.decision
    assert_includes result.reason, UNANALYSABLE_SENTENCE
    assert_match(/protected-(?:a|b)\.txt/, result.reason)
    refute_includes result.reason, "unrelated.txt"
    refute_includes result.reason, "agent-acl allow edit"
  end

  def test_denies_unbalanced_shell_quotes_as_unanalysable
    write_manifest("protected.txt")

    result = run_guard(
      "tool_name" => "Bash",
      "tool_input" => { "command" => 'grep -n "unterminated unprotected.txt' }
    )

    assert_equal 0, result.exitstatus
    assert_equal "deny", result.decision
    assert_includes result.reason, UNANALYSABLE_SENTENCE
    refute_includes result.reason, "agent-acl guard error"
    refute_includes result.reason, "protected.txt"
    refute_includes result.reason, "agent-acl allow edit"
  end

  def test_allows_an_allowlisted_executable_to_read_a_protected_path
    write_manifest("protected.txt")
    write_executable_allowlist("custom-reader")

    result = run_guard(
      "tool_name" => "Bash",
      "tool_input" => { "command" => "custom-reader protected.txt" }
    )

    assert_equal 0, result.exitstatus
    assert_equal "", result.stdout
  end

  def test_executable_allowlist_does_not_override_known_mutators
    write_manifest("protected.txt")
    write_executable_allowlist("git", "less", "rm", "sed")

    [
      "git checkout -- protected.txt",
      "git clean -f protected.txt",
      "less -O protected.txt README.md",
      "less --log-file=protected.txt README.md",
      "rm protected.txt",
      "sed -i '' 's/a/b/' protected.txt"
    ].each do |command|
      result = run_guard(
        "tool_name" => "Bash",
        "tool_input" => { "command" => command }
      )

      assert_equal 0, result.exitstatus, command
      assert_equal "deny", result.decision, command
      assert_includes result.reason, DENY_SENTENCE, command
      assert_includes result.reason, "protected.txt", command
    end
  end

  def test_executable_allowlist_does_not_override_sed_write_scripts
    write_manifest("protected.txt")
    write_executable_allowlist("sed")

    [
      "sed -n 'w protected.txt' input.txt",
      "sed -e '1w protected.txt' input.txt"
    ].each do |command|
      result = run_guard(
        "tool_name" => "Bash",
        "tool_input" => { "command" => command }
      )

      assert_equal 0, result.exitstatus, command
      assert_equal "deny", result.decision, command
      assert_includes result.reason, UNANALYSABLE_SENTENCE, command
      refute_includes result.reason, DENY_SENTENCE, command
      assert_includes result.reason, "protected.txt", command
    end
  end

  def test_confirmed_modification_takes_precedence_over_an_unanalysable_segment
    write_manifest("protected-a.txt", "protected-b.txt")

    [
      "rm protected-a.txt; arbitrary protected-b.txt",
      "arbitrary protected-b.txt; rm protected-a.txt",
      "rm protected-a.txt; false && p=x",
      'rm protected-a.txt; echo "$MISSING"',
      "rm protected-a.txt; p=$MISSING"
    ].each do |command|
      result = run_guard(
        "tool_name" => "Bash",
        "tool_input" => { "command" => command }
      )

      assert_equal 0, result.exitstatus, command
      assert_equal "deny", result.decision, command
      assert_includes result.reason, DENY_SENTENCE, command
      refute_includes result.reason, UNANALYSABLE_SENTENCE, command
      assert_includes result.reason, "protected-a.txt", command
      refute_includes result.reason, "protected-b.txt", command
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
      "less -osecret README.md",
      "less -Osecret README.md",
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

  def test_allows_protected_read_operands_with_unprotected_output_options
    write_manifest("protected.txt")

    [
      "git diff --output=unprotected.diff -- protected.txt",
      "git diff --output unprotected.diff -- protected.txt",
      "less -O unprotected.log protected.txt",
      "less --log-file=unprotected.log protected.txt"
    ].each do |command|
      result = run_guard(
        "tool_name" => "Bash",
        "tool_input" => { "command" => command }
      )

      assert_equal 0, result.exitstatus, command
      assert_equal "", result.stdout, command
    end
  end

  def test_denies_read_only_commands_with_protected_assignment_values_as_unanalysable
    write_manifest("protected.txt")
    protected_path = File.join(@root, "protected.txt")

    [
      "GIT_TRACE=#{protected_path} git status",
      "LESSHISTFILE=#{protected_path} less README.md"
    ].each do |command|
      result = run_guard(
        "tool_name" => "Bash",
        "tool_input" => { "command" => command }
      )

      assert_equal 0, result.exitstatus, command
      assert_equal "deny", result.decision, command
      assert_includes result.reason, UNANALYSABLE_SENTENCE, command
      refute_includes result.reason, DENY_SENTENCE, command
      assert_includes result.reason, "protected.txt", command
    end
  end

  def test_denies_persistent_protected_assignments_as_unanalysable
    write_manifest("protected.txt")
    protected_path = File.join(@root, "protected.txt")

    [
      "GIT_TRACE=#{protected_path}; git status",
      "export GIT_TRACE=#{protected_path}; git status",
      "GIT_TRACE=#{protected_path}; export GIT_TRACE; git status"
    ].each do |command|
      result = run_guard(
        "tool_name" => "Bash",
        "tool_input" => { "command" => command }
      )

      assert_equal 0, result.exitstatus, command
      assert_equal "deny", result.decision, command
      assert_includes result.reason, UNANALYSABLE_SENTENCE, command
      refute_includes result.reason, DENY_SENTENCE, command
      assert_includes result.reason, "protected.txt", command
    end
  end

  def test_allows_protected_sources_for_directional_copy_commands
    write_manifest("protected.txt")

    [
      "cp protected.txt unprotected.txt",
      "dd if=protected.txt of=unprotected.txt",
      "install protected.txt unprotected.txt",
      "rsync protected.txt unprotected.txt"
    ].each do |command|
      result = run_guard(
        "tool_name" => "Bash",
        "tool_input" => { "command" => command }
      )

      assert_equal 0, result.exitstatus, command
      assert_equal "", result.stdout, command
    end
  end

  def test_allows_option_bearing_protected_sources_for_directional_copy_commands
    write_manifest("protected.txt")

    [
      "cp -p protected.txt copy.txt",
      "cp -- protected.txt copy.txt",
      "install -m 644 protected.txt copy.txt",
      "rsync -a protected.txt copy.txt"
    ].each do |command|
      result = run_guard(
        "tool_name" => "Bash",
        "tool_input" => { "command" => command }
      )

      assert_equal 0, result.exitstatus, command
      assert_equal "", result.stdout, command
    end
  end

  def test_denies_protected_destinations_for_directional_copy_commands
    write_manifest("protected.txt")

    [
      "cp unprotected.txt protected.txt",
      "dd if=unprotected.txt of=protected.txt",
      "install unprotected.txt protected.txt",
      "rsync unprotected.txt protected.txt"
    ].each do |command|
      result = run_guard(
        "tool_name" => "Bash",
        "tool_input" => { "command" => command }
      )

      assert_equal 0, result.exitstatus, command
      assert_equal "deny", result.decision, command
      assert_includes result.reason, DENY_SENTENCE, command
      assert_includes result.reason, "protected.txt", command
    end
  end

  def test_denies_protected_target_directories_for_cp_and_install
    write_manifest("protected/source.txt")

    %w[cp install].product(
      [
        "-tprotected source.txt",
        "-t protected source.txt",
        "--target-directory=protected source.txt",
        "--target-directory protected source.txt"
      ]
    ).each do |executable, arguments|
      command = "#{executable} #{arguments}"
      result = run_guard(
        "tool_name" => "Bash",
        "tool_input" => { "command" => command }
      )

      assert_equal 0, result.exitstatus, command
      assert_equal "deny", result.decision, command
      assert_includes result.reason, DENY_SENTENCE, command
      assert_includes result.reason, "protected/source.txt", command
    end
  end

  def test_denies_ansi_c_quoted_shell_mutations_as_unanalysable
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
      assert_includes result.reason, UNANALYSABLE_SENTENCE, command
      refute_includes result.reason, DENY_SENTENCE, command
    end
  end

  def test_denies_unquoted_shell_parentheses_as_unanalysable
    write_manifest("protected.txt")

    [
      "rm @(protected.txt)",
      "rm +(protected.txt)"
    ].each do |command|
      result = run_guard(
        "tool_name" => "Bash",
        "tool_input" => { "command" => command }
      )

      assert_equal 0, result.exitstatus, command
      assert_equal "deny", result.decision, command
      assert_includes result.reason, UNANALYSABLE_SENTENCE, command
      refute_includes result.reason, DENY_SENTENCE, command
    end
  end

  def test_denies_shell_writes_and_unlock_attempts
    write_manifest("LICENSE")

    [
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

  def test_existing_shell_mutators_name_the_referenced_protected_path
    write_manifest("unrelated.txt", "protected.txt")

    [
      "rm protected.txt",
      "mv protected.txt moved.txt",
      "cp README.md protected.txt",
      "printf content | tee protected.txt",
      "truncate -s 0 protected.txt",
      "printf content > protected.txt",
      "printf content>protected.txt",
      "printf content>>protected.txt"
    ].each do |command|
      result = run_guard(
        "tool_name" => "Bash",
        "tool_input" => { "command" => command }
      )

      assert_equal 0, result.exitstatus, command
      assert_equal "deny", result.decision, command
      assert_includes result.reason, DENY_SENTENCE, command
      assert_includes result.reason, "protected.txt", command
      refute_includes result.reason, "unrelated.txt", command
    end
  end

  def test_redirection_variants_are_confirmed_modification_denials
    write_manifest("unrelated.txt", "protected.txt")

    [
      "printf content >| protected.txt",
      "printf content>|protected.txt",
      "printf content &> protected.txt",
      "printf content >& protected.txt"
    ].each do |command|
      result = run_guard(
        "tool_name" => "Bash",
        "tool_input" => { "command" => command }
      )

      assert_equal 0, result.exitstatus, command
      assert_equal "deny", result.decision, command
      assert_includes result.reason, DENY_SENTENCE, command
      refute_includes result.reason, UNANALYSABLE_SENTENCE, command
      assert_includes result.reason, "protected.txt", command
      refute_includes result.reason, "unrelated.txt", command
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

  def test_denies_shell_execution_hidden_inside_a_read_only_command_as_unanalysable
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
      assert_includes result.reason, UNANALYSABLE_SENTENCE, command
      refute_includes result.reason, DENY_SENTENCE, command
    end
  end

  def test_allows_interpreters_and_unknown_effect_commands_without_a_literal_path
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
      assert_equal "", result.stdout, command
    end
  end

  def test_resolves_escaped_globbed_nested_and_variable_shell_paths
    write_manifest("dir/LICENSE", "my notes.md")

    [
      "cd dir; rm LICENSE",
      "cd -- dir; rm LICENSE",
      "cd -P dir; rm LICENSE",
      "cd -L dir; rm LICENSE",
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
      sentence = command.match?(/\Agit (?:clean|add)\b/) ? UNANALYSABLE_SENTENCE : DENY_SENTENCE
      assert_includes result.reason, sentence, command
    end
  end

  def test_tracks_a_hyphenated_directory_after_cd_end_of_options
    write_manifest("-dir/LICENSE")

    result = run_guard(
      "tool_name" => "Bash",
      "tool_input" => { "command" => "cd -- -dir; rm LICENSE" }
    )

    assert_equal 0, result.exitstatus
    assert_equal "deny", result.decision
    assert_includes result.reason, DENY_SENTENCE
    assert_includes result.reason, "-dir/LICENSE"
  end

  def test_tracks_a_hyphenated_operand_after_end_of_options
    write_manifest("dir/-secret", "dir/-target")

    [
      "cd dir; rm -- -secret",
      "cd dir; cp source -- -target",
      "cd dir; install source -- -target"
    ].each do |command|
      result = run_guard(
        "tool_name" => "Bash",
        "tool_input" => { "command" => command }
      )

      assert_equal 0, result.exitstatus, command
      assert_equal "deny", result.decision, command
      assert_includes result.reason, DENY_SENTENCE, command
      assert_match(%r{dir/-(?:secret|target)}, result.reason, command)
    end
  end

  def test_resolves_relative_display_paths_from_the_tracked_directory
    write_manifest("dir/LICENSE")

    result = run_guard(
      "tool_name" => "Bash",
      "tool_input" => { "command" => "cd other; rm dir/LICENSE" }
    )

    assert_equal 0, result.exitstatus
    assert_equal "", result.stdout
  end

  def test_does_not_match_a_relative_manifest_path_inside_a_longer_path
    write_manifest("dir/LICENSE")

    result = run_guard(
      "tool_name" => "Bash",
      "tool_input" => { "command" => "rm other/dir/LICENSE" }
    )

    assert_equal 0, result.exitstatus
    assert_equal "", result.stdout
  end

  def test_expands_tilde_operands_against_the_inherited_home
    write_manifest("dir/LICENSE")

    [
      "cd other; rm ~/dir/LICENSE",
      "cd other; printf content > ~/dir/LICENSE",
      "cd other; cp source ~/dir/LICENSE",
      "cd other; less -O ~/dir/LICENSE README.md"
    ].each do |command|
      result = run_guard(
        {
          "tool_name" => "Bash",
          "tool_input" => { "command" => command }
        },
        env: { "HOME" => @root }
      )

      assert_equal 0, result.exitstatus, command
      assert_equal "deny", result.decision, command
      assert_includes result.reason, DENY_SENTENCE, command
      assert_includes result.reason, "dir/LICENSE", command
    end
  end

  def test_keeps_quoted_and_escaped_tilde_operands_literal
    write_manifest("dir/LICENSE")

    [
      "cd other; rm '~/dir/LICENSE'",
      "cd other; rm \\~/dir/LICENSE",
      "cd other; printf content > '~/dir/LICENSE'",
      "cd other; printf content > \\~/dir/LICENSE",
      "cd other; cp source '~/dir/LICENSE'",
      "cd other; less -O '~/dir/LICENSE' README.md"
    ].each do |command|
      result = run_guard(
        {
          "tool_name" => "Bash",
          "tool_input" => { "command" => command }
        },
        env: { "HOME" => @root }
      )

      assert_equal 0, result.exitstatus, command
      assert_equal "", result.stdout, command
    end
  end

  def test_treats_mixed_tilde_quote_state_as_unanalysable
    write_manifest("dir/LICENSE")

    result = run_guard(
      {
        "tool_name" => "Bash",
        "tool_input" => { "command" => "cat ~/dir/LICENSE > '~/dir/LICENSE'" }
      },
      env: { "HOME" => @root }
    )

    assert_equal 0, result.exitstatus
    assert_equal "deny", result.decision
    assert_includes result.reason, UNANALYSABLE_SENTENCE
    refute_includes result.reason, DENY_SENTENCE
  end

  def test_denies_home_and_previous_directory_changes_as_unanalysable
    write_manifest("other/LICENSE")

    [
      "cd; rm LICENSE",
      "cd -; rm LICENSE",
      "cd dir; cd -; cd other; rm LICENSE"
    ].each do |command|
      result = run_guard(
        "tool_name" => "Bash",
        "tool_input" => { "command" => command }
      )

      assert_equal 0, result.exitstatus, command
      assert_equal "deny", result.decision, command
      assert_includes result.reason, UNANALYSABLE_SENTENCE, command
      refute_includes result.reason, DENY_SENTENCE, command
    end
  end

  def test_confirmed_modification_precedes_a_later_ambiguous_directory_change
    write_manifest("protected.txt")

    result = run_guard(
      "tool_name" => "Bash",
      "tool_input" => { "command" => "rm protected.txt; cd -" }
    )

    assert_equal 0, result.exitstatus
    assert_equal "deny", result.decision
    assert_includes result.reason, DENY_SENTENCE
    refute_includes result.reason, UNANALYSABLE_SENTENCE
    assert_includes result.reason, "protected.txt"
  end

  def test_denies_assignment_prefixed_home_directory_change_as_unanalysable
    write_manifest("dir/LICENSE")

    result = run_guard(
      "tool_name" => "Bash",
      "tool_input" => { "command" => "HOME=dir cd; rm LICENSE" }
    )

    assert_equal 0, result.exitstatus
    assert_equal "deny", result.decision
    assert_includes result.reason, UNANALYSABLE_SENTENCE
    refute_includes result.reason, DENY_SENTENCE
  end

  def test_denies_cdpath_dependent_directory_changes_as_unanalysable
    write_manifest("base/dir/LICENSE")

    [
      "CDPATH=base cd dir; rm LICENSE",
      "export CDPATH=base; cd dir; rm LICENSE",
      "CDPATH=base; export CDPATH; cd dir; rm LICENSE",
      "CDPATH=:base; cd dir; rm LICENSE",
      "export CDPATH=:base; cd dir; rm LICENSE"
    ].each do |command|
      result = run_guard(
        "tool_name" => "Bash",
        "tool_input" => { "command" => command }
      )

      assert_equal 0, result.exitstatus, command
      assert_equal "deny", result.decision, command
      assert_includes result.reason, UNANALYSABLE_SENTENCE, command
      refute_includes result.reason, DENY_SENTENCE, command
    end
  end

  def test_denies_tilde_dependent_directory_changes_as_unanalysable
    write_manifest("dir/LICENSE")

    [
      "cd ~/dir; rm LICENSE",
      "HOME=.; cd ~/dir; rm LICENSE"
    ].each do |command|
      result = run_guard(
        "tool_name" => "Bash",
        "tool_input" => { "command" => command }
      )

      assert_equal 0, result.exitstatus, command
      assert_equal "deny", result.decision, command
      assert_includes result.reason, UNANALYSABLE_SENTENCE, command
      refute_includes result.reason, DENY_SENTENCE, command
    end
  end

  def test_denies_untracked_directory_stack_changes_as_unanalysable
    write_manifest("dir/LICENSE")

    [
      "pushd dir; rm LICENSE",
      "pushd dir >/dev/null; rm LICENSE"
    ].each do |command|
      result = run_guard(
        "tool_name" => "Bash",
        "tool_input" => { "command" => command }
      )

      assert_equal 0, result.exitstatus, command
      assert_equal "deny", result.decision, command
      assert_includes result.reason, UNANALYSABLE_SENTENCE, command
      refute_includes result.reason, DENY_SENTENCE, command
      assert_includes result.reason, "dir/LICENSE", command
    end
  end

  def test_resolves_dependent_shell_assignments_in_execution_order
    write_manifest("dir/LICENSE")

    result = run_guard(
      "tool_name" => "Bash",
      "tool_input" => { "command" => 'b=dir/LICENSE; c=$b; rm "$c"' }
    )

    assert_equal 0, result.exitstatus
    assert_equal "deny", result.decision
    assert_includes result.reason, DENY_SENTENCE
    refute_includes result.reason, UNANALYSABLE_SENTENCE
    assert_includes result.reason, "dir/LICENSE"
  end

  def test_expands_reassigned_variables_in_shell_execution_order
    write_manifest("protected.txt")

    [
      'p=protected.txt; rm "$p"; p=unprotected.txt',
      'p=protected.txt; p=unprotected.txt true; rm "$p"',
      'p=unprotected.txt; p=protected.txt export p; rm "$p"'
    ].each do |command|
      result = run_guard(
        "tool_name" => "Bash",
        "tool_input" => { "command" => command }
      )

      assert_equal 0, result.exitstatus, command
      assert_equal "deny", result.decision, command
      assert_includes result.reason, DENY_SENTENCE, command
      assert_includes result.reason, "protected.txt", command
    end
  end

  def test_denies_nonsequential_variable_state_changes_as_unanalysable
    write_manifest("protected.txt")

    [
      'p=protected.txt; false && p=unprotected.txt; rm "$p"',
      'p=protected.txt; true || p=unprotected.txt; rm "$p"',
      'p=protected.txt; p=unprotected.txt | cat; rm "$p"'
    ].each do |command|
      result = run_guard(
        "tool_name" => "Bash",
        "tool_input" => { "command" => command }
      )

      assert_equal 0, result.exitstatus, command
      assert_equal "deny", result.decision, command
      assert_includes result.reason, UNANALYSABLE_SENTENCE, command
      refute_includes result.reason, DENY_SENTENCE, command
    end
  end

  def test_allows_pipeline_local_environment_assignments_without_protected_paths
    write_manifest("protected.txt")

    [
      "FOO=x arbitrary-reader README.md | cat",
      "FOO=x echo ok | cat"
    ].each do |command|
      result = run_guard(
        "tool_name" => "Bash",
        "tool_input" => { "command" => command }
      )

      assert_equal 0, result.exitstatus, command
      assert_equal "", result.stdout, command
    end
  end

  def test_denies_nonsequential_control_flow_with_directory_changes_as_unanalysable
    write_manifest("dir/LICENSE")

    [
      "cd dir; false && cd ../other; rm LICENSE",
      "cd dir; true || cd ../other; rm LICENSE",
      "cd dir; cd ../other | cat; rm LICENSE"
    ].each do |command|
      result = run_guard(
        "tool_name" => "Bash",
        "tool_input" => { "command" => command }
      )

      assert_equal 0, result.exitstatus, command
      assert_equal "deny", result.decision, command
      assert_includes result.reason, UNANALYSABLE_SENTENCE, command
      refute_includes result.reason, DENY_SENTENCE, command
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

  def test_same_basename_in_another_directory_is_not_overmatched
    write_manifest("dir/LICENSE")
    FileUtils.mkdir_p(File.join(@root, "other"))
    File.write(File.join(@root, "other", "LICENSE"), "content")

    result = run_guard(
      "tool_name" => "Bash",
      "tool_input" => { "command" => "rm other/LICENSE" }
    )

    assert_equal 0, result.exitstatus
    assert_equal "", result.stdout
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
    assert_includes result.reason, "agent-acl guard error (JSON::ParserError:"
    refute_includes result.reason, DENY_SENTENCE
    refute_includes result.reason, "agent-acl allow edit"
  end

  def test_fails_closed_when_payload_json_is_not_an_object
    write_manifest("LICENSE")

    result = run_raw_guard(JSON.generate("not an object"))

    assert_equal 0, result.exitstatus
    assert_equal "deny", result.decision
    assert_includes result.reason, "agent-acl guard error (TypeError:"
    refute_includes result.reason, DENY_SENTENCE
  end

  def test_fails_closed_when_a_known_tool_has_an_unrecognized_shape
    write_manifest("LICENSE")

    result = run_guard("tool_name" => "Edit", "tool_input" => {})

    assert_equal 0, result.exitstatus
    assert_equal "deny", result.decision
    assert_includes result.reason, "agent-acl guard error (KeyError:"
    refute_includes result.reason, DENY_SENTENCE
  end

  def test_passes_guard_errors_when_nothing_is_protected
    result = run_raw_guard("not json")

    assert_equal 0, result.exitstatus
    assert_equal "", result.stdout
  end

  def test_passes_everything_with_an_empty_manifest
    File.write(File.join(@root, ".agent-acl"), "")

    result = run_guard(
      "tool_name" => "Bash",
      "tool_input" => { "command" => 'grep -n "unterminated' }
    )

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
    assert_includes result.reason, "agent-acl guard error (ArgumentError:"
    refute_includes result.reason, DENY_SENTENCE
    refute_includes result.reason, "agent-acl allow edit"
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

  def run_guard(payload = nil, env: {}, **payload_keywords)
    payload ||= payload_keywords
    run_raw_guard(JSON.generate(payload), env: env)
  end

  def run_raw_guard(stdin_data, env: {})
    assert File.exist?(GUARD_TEMPLATE_PATH), "expected guard template to exist at #{GUARD_TEMPLATE_PATH}"

    stdout, stderr, status = Open3.capture3(
      env,
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

  def write_executable_allowlist(*executables)
    directory = File.join(@root, ".agent-acl.d")
    FileUtils.mkdir_p(directory)
    File.write(File.join(directory, "executables.allow"), executables.join("\n"))
  end

  def create_filesystem_aliases(path)
    File.symlink(path, File.join(@root, "#{path}-link"))
    File.symlink(path, File.join(@root, "alias"))
    File.symlink(path, File.join(@root, "a=b"))
    File.link(File.join(@root, path), File.join(@root, "#{path}-hardlink"))
  end
end
