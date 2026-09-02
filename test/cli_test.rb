# frozen_string_literal: true

require "test_helper"

class CliTest < Minitest::Test
  FakeResult = Data.define(:full, :warnings)

  class FakeGuard
    attr_reader :calls

    def initialize(result: FakeResult.new(full: true, warnings: []), error: nil)
      @result = result
      @error = error
      @calls = []
    end

    def protect
      calls << [:protect]
      fail @error if @error

      @result
    end

    def unprotect(mode:)
      calls << [:unprotect, mode]
      fail @error if @error

      @result
    end
  end

  class FakeInstaller
    attr_reader :calls

    def initialize
      @calls = []
    end

    def install = calls << :install
    def sync = calls << :sync
  end

  class FailingInstaller < FakeInstaller
    def install
      super
      fail "broken config"
    end
  end

  def test_list_is_empty_when_no_manifest_exists
    in_project do |root, out, err|
      status = AgentAcl::CLI.new(root:, out:, err:).run(["list"])

      assert_equal 0, status
      assert_equal "", out.string
      assert_equal "", err.string
    end
  end

  def test_list_prints_one_blocked_edit_per_line
    in_project do |root, out, err|
      manifest = AgentAcl::Manifest.load(root)
      manifest.add("first file", mode: 0o644)
      manifest.add("second", mode: 0o755)
      manifest.write

      status = AgentAcl::CLI.new(root:, out:, err:).run(["list"])

      assert_equal 0, status
      assert_equal "edit blocked -> first file\nedit blocked -> second\n", out.string
      assert_equal "", err.string
    end
  end

  def test_version_prints_the_gem_version
    in_project do |root, out, err|
      status = AgentAcl::CLI.new(root:, out:, err:).run(["version"])

      assert_equal 0, status
      assert_equal "#{AgentAcl::VERSION}\n", out.string
      assert_equal "", err.string
    end
  end

  def test_invalid_command_becomes_an_error_status
    in_project do |root, out, err|
      status = AgentAcl::CLI.new(root:, out:, err:).run(["wat"])

      assert_equal 1, status
      assert_equal "", out.string
      assert_includes err.string, "Usage:"
    end
  end

  def test_block_protects_a_regular_file_and_records_its_mode
    in_project do |root, out, err|
      path = File.join(root, "my notes.md")
      File.write(path, "notes")
      File.chmod(0o640, path)
      guard = FakeGuard.new
      installers = Array.new(3) { FakeInstaller.new }
      cli = build_cli(root, out, err, guard:, installers:)

      status = cli.run(["block", "edit", "my notes.md"])

      assert_equal 0, status
      assert_equal [[:protect]], guard.calls
      assert_equal([["my notes.md", 0o640]], AgentAcl::Manifest.load(root).entries.map { [_1.path, _1.mode] })
      assert(installers.all? { _1.calls == [:install] })
      assert_includes out.string, "protected my notes.md"
      assert_equal "", err.string
    end
  end

  def test_block_validates_every_target_before_changing_anything
    in_project do |root, out, err|
      File.write(File.join(root, "valid"), "content")
      guard = FakeGuard.new
      cli = build_cli(root, out, err, guard:)

      status = cli.run(%w[block edit valid missing])

      assert_equal 1, status
      assert_empty guard.calls
      refute File.exist?(File.join(root, ".agent-acl"))
      assert_includes err.string, "not found"
    end
  end

  def test_block_rejects_directories_symlinks_and_outside_paths_without_writes
    in_project do |root, out, err|
      outside = File.join(File.dirname(root), "outside")
      File.write(outside, "outside")
      FileUtils.mkdir_p(File.join(root, "directory"))
      File.symlink(outside, File.join(root, "link"))

      {
        "directory" => "directory",
        "link" => "symlink",
        outside => "inside the project"
      }.each do |target, message|
        guard = FakeGuard.new
        status = build_cli(root, out, err, guard:).run(["block", "edit", target])

        assert_equal 1, status
        assert_empty guard.calls
        assert_includes err.string, message
        refute File.exist?(File.join(root, ".agent-acl"))
        err.truncate(0)
        err.rewind
      end
    ensure
      FileUtils.rm_f(outside) if outside
    end
  end

  def test_block_rejects_a_file_reached_through_a_symlinked_directory
    in_project do |root, out, err|
      Dir.mktmpdir do |outside|
        File.write(File.join(outside, "file"), "outside")
        File.symlink(outside, File.join(root, "linked-directory"))
        guard = FakeGuard.new

        status = build_cli(root, out, err, guard:).run(%w[block edit linked-directory/file])

        assert_equal 1, status
        assert_empty guard.calls
        assert_includes err.string, "inside the project"
        refute File.exist?(File.join(root, ".agent-acl"))
      end
    end
  end

  def test_block_rejects_names_that_agent_rule_syntax_cannot_represent_safely
    in_project do |root, out, err|
      unsafe_name = "data[1].txt"
      File.write(File.join(root, unsafe_name), "content")
      guard = FakeGuard.new

      status = build_cli(root, out, err, guard:).run(["block", "edit", unsafe_name])

      assert_equal 1, status
      assert_empty guard.calls
      assert_includes err.string, "unsupported characters"
      refute File.exist?(File.join(root, ".agent-acl"))
    end
  end

  def test_reblock_repairs_layers_without_replacing_the_original_mode
    in_project do |root, out, err|
      path = File.join(root, "LICENSE")
      File.write(path, "license")
      manifest = AgentAcl::Manifest.load(root)
      manifest.add(path, mode: 0o755)
      manifest.write
      File.chmod(0o444, path)
      guard = FakeGuard.new

      status = build_cli(root, out, err, guard:).run(%w[block edit LICENSE])

      assert_equal 0, status
      assert_equal 0o755, AgentAcl::Manifest.load(root).entries.first.mode
      assert_includes out.string, "already protected, re-applied"
    end
  end

  def test_block_prints_linux_degradation_warnings
    in_project do |root, out, err|
      File.write(File.join(root, "LICENSE"), "license")
      warning = "delete and rename are not OS-blocked; run sudo agent-acl block edit LICENSE"
      guard = FakeGuard.new(result: FakeResult.new(full: false, warnings: [warning]))

      status = build_cli(root, out, err, guard:).run(%w[block edit LICENSE])

      assert_equal 0, status
      assert_includes err.string, warning
    end
  end

  def test_block_attempts_every_installer_and_reports_partial_configuration
    in_project do |root, out, err|
      File.write(File.join(root, "LICENSE"), "license")
      installers = [FailingInstaller.new, FakeInstaller.new, FakeInstaller.new]

      status = build_cli(root, out, err, guard: FakeGuard.new, installers:).run(%w[block edit LICENSE])

      assert_equal 1, status
      assert_equal [[:install], [:install], [:install]], installers.map(&:calls)
      assert_includes err.string, "agent configuration is partial"
      assert AgentAcl::Manifest.load(root).protected?("LICENSE")
    end
  end

  def test_allow_restores_the_recorded_mode_then_syncs_agent_config
    in_project do |root, out, err|
      path = File.join(root, "LICENSE")
      File.write(path, "license")
      manifest = AgentAcl::Manifest.load(root)
      manifest.add(path, mode: 0o755)
      manifest.write
      guard = FakeGuard.new
      installers = Array.new(3) { FakeInstaller.new }

      status = build_cli(root, out, err, guard:, installers:).run(%w[allow edit LICENSE])

      assert_equal 0, status
      assert_equal [[:unprotect, 0o755]], guard.calls
      assert_empty AgentAcl::Manifest.load(root).entries
      assert(installers.all? { _1.calls == [:sync] })
      assert_includes out.string, "allowed edits to LICENSE"
    end
  end

  def test_allow_on_an_unprotected_file_is_idempotent
    in_project do |root, out, err|
      File.write(File.join(root, "LICENSE"), "license")
      guard = FakeGuard.new

      status = build_cli(root, out, err, guard:).run(%w[allow edit LICENSE])

      assert_equal 0, status
      assert_empty guard.calls
      assert_includes out.string, "not protected"
      assert_equal "", err.string
    end
  end

  def test_allow_keeps_manifest_when_the_os_guard_needs_sudo
    in_project do |root, out, err|
      path = File.join(root, "LICENSE")
      File.write(path, "license")
      manifest = AgentAcl::Manifest.load(root)
      manifest.add(path, mode: 0o644)
      manifest.write
      guard = FakeGuard.new(error: AgentAcl::NeedsSudo.new("run with sudo"))

      status = build_cli(root, out, err, guard:).run(%w[allow edit LICENSE])

      assert_equal 1, status
      assert AgentAcl::Manifest.load(root).protected?(path)
      assert_includes err.string, "run with sudo"
    end
  end

  private

  def build_cli(root, out, err, guard:, installers: [])
    guards = Hash.new(guard)
    guard_factory = ->(path:) { guards[path] }
    installer_factories = installers.map { |installer| ->(**) { installer } }
    AgentAcl::CLI.new(root:, out:, err:, os_guard_factory: guard_factory, installer_factories:)
  end

  def in_project
    Dir.mktmpdir do |root|
      yield root, StringIO.new, StringIO.new
    end
  end
end
