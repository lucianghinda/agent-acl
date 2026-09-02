# frozen_string_literal: true

require "test_helper"

class OsGuardTest < Minitest::Test
  FakeRunner = Struct.new(:captures, :commands, :error, keyword_init: true) do
    def capture(*command)
      commands << command
      captured = captures.fetch(command.first, "")
      captured.is_a?(Array) ? captured.shift.to_s : captured
    end

    def run(*command)
      commands << command
      fail error if error
    end
  end

  def test_rejects_an_unsupported_platform_before_changing_the_file
    with_file(mode: 0o644) do |path|
      runner = fake_runner
      guard = AgentAcl::OsGuard.new(path:, platform: "mswin", runner:)

      assert_raises(AgentAcl::Unsupported) { guard.protect }
      assert_equal 0o644, mode_of(path)
      assert_empty runner.commands
    end
  end

  def test_macos_removes_write_bits_and_applies_the_user_immutable_flag
    with_file(mode: 0o755) do |path|
      runner = fake_runner({ "ls" => ["-rwxr-xr-x 1 user staff - 1 Sep 1 00:00 file\n",
                                      "-r-xr-xr-x 1 user staff uchg 1 Sep 1 00:00 file\n"] })
      guard = AgentAcl::OsGuard.new(path:, platform: "darwin", runner:)

      result = guard.protect

      assert result.full
      assert_empty result.warnings
      assert_equal 0o555, mode_of(path)
      assert_includes runner.commands, ["chflags", "uchg", path]
      assert guard.os_locked?
    end
  end

  def test_linux_without_root_degrades_loudly
    with_file(mode: 0o644) do |path|
      runner = fake_runner
      guard = AgentAcl::OsGuard.new(path:, platform: "linux", root_user: false, runner:)

      result = guard.protect

      refute result.full
      assert_equal 0o444, mode_of(path)
      assert_equal 1, result.warnings.length
      assert_includes result.warnings.first, "delete and rename"
      assert_includes result.warnings.first, "sudo agent-acl block edit"
      refute(runner.commands.any? { _1.first == "chattr" })
    end
  end

  def test_linux_with_root_applies_the_immutable_attribute
    with_file do |path|
      runner = fake_runner
      guard = AgentAcl::OsGuard.new(path:, platform: "linux", root_user: true, runner:)

      result = guard.protect

      assert result.full
      assert_includes runner.commands, ["chattr", "+i", path]
    end
  end

  def test_protect_restores_the_original_mode_when_the_flag_command_fails
    with_file(mode: 0o755) do |path|
      runner = fake_runner(error: AgentAcl::Error.new("chflags unavailable"))
      guard = AgentAcl::OsGuard.new(path:, platform: "darwin", runner:)

      error = assert_raises(AgentAcl::Error) { guard.protect }

      assert_includes error.message, "chflags unavailable"
      assert_equal 0o755, mode_of(path)
    end
  end

  def test_unprotect_lifts_macos_flag_before_restoring_the_mode
    with_file(mode: 0o444) do |path|
      runner = fake_runner({ "ls" => "-r--r--r-- 1 user staff uchg 1 Sep 1 00:00 file\n" })
      guard = AgentAcl::OsGuard.new(path:, platform: "darwin", runner:)

      result = guard.unprotect(mode: 0o755)

      assert result.full
      assert_equal 0o755, mode_of(path)
      assert_equal ["ls", "-ldO", path], runner.commands[0]
      assert_equal ["chflags", "nouchg", path], runner.commands[1]
    end
  end

  def test_linux_allow_requires_root_when_immutable
    with_file(mode: 0o444) do |path|
      runner = fake_runner({ "lsattr" => "----i--------e------- #{path}\n" })
      guard = AgentAcl::OsGuard.new(path:, platform: "linux", root_user: false, runner:)

      error = assert_raises(AgentAcl::NeedsSudo) { guard.unprotect(mode: 0o644) }

      assert_includes error.message, "sudo"
      assert_equal 0o444, mode_of(path)
      refute(runner.commands.any? { _1.first == "chattr" })
    end
  end

  def test_unprotect_restores_mode_when_the_flag_was_lifted_by_hand
    with_file(mode: 0o444) do |path|
      runner = fake_runner({ "ls" => "-r--r--r-- 1 user staff - 1 Sep 1 00:00 file\n" })
      guard = AgentAcl::OsGuard.new(path:, platform: "darwin", runner:)

      guard.unprotect(mode: 0o644)

      assert_equal 0o644, mode_of(path)
      refute(runner.commands.any? { _1.first == "chflags" })
    end
  end

  private

  def fake_runner(captures = {}, error: nil)
    FakeRunner.new(captures:, commands: [], error:)
  end

  def with_file(mode: 0o644)
    Dir.mktmpdir do |directory|
      path = File.join(directory, "file")
      File.write(path, "content")
      File.chmod(mode, path)
      yield path
    end
  end

  def mode_of(path)
    File.stat(path).mode & 0o7777
  end
end
