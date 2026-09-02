# frozen_string_literal: true

require "open3"
require "shellwords"

module AgentAcl
  # Applies and removes platform file protections while preserving file modes.
  class OsGuard
    Result = Data.define(:full, :warnings)

    class CommandRunner
      def capture(*command)
        output, status = Open3.capture2e(*command)
        fail Error, "#{command.first} failed: #{output.strip}" unless status.success?

        output
      end

      def run(*command)
        capture(*command)
        nil
      end
    end

    attr_reader :path

    # @param path [String] file to protect
    # @param platform [String] Ruby platform identifier
    # @param root_user [Boolean] whether immutable Linux flags may be changed
    def initialize(path:, platform: RUBY_PLATFORM, root_user: Process.euid.zero?, runner: CommandRunner.new)
      @path = File.expand_path(path)
      @platform = platform
      @root_user = root_user
      @runner = runner
    end

    # Removes write bits and applies the platform immutable flag when available.
    # @return [Result]
    def protect
      assert_supported!
      return Result.new(full: true, warnings: []) if os_locked?

      original_mode = File.stat(path).mode & 0o7777
      remove_write_bits
      apply_platform_lock
    rescue StandardError => e
      restore_mode_after_failed_protect(original_mode) if original_mode
      raise e
    end

    def apply_platform_lock
      return protect_macos if macos?
      return protect_linux if root_user

      Result.new(full: false, warnings: [linux_warning])
    end
    private :apply_platform_lock

    # Removes platform protection and restores a recorded mode.
    # @param mode [Integer]
    # @return [Result]
    def unprotect(mode:)
      assert_supported!
      locked = os_locked?
      fail NeedsSudo, "run with sudo to lift the immutable attribute on #{path}" if linux? && locked && !root_user

      runner.run("chflags", "nouchg", path) if macos? && locked
      runner.run("chattr", "-i", path) if linux? && locked
      File.chmod(mode, path)
      Result.new(full: true, warnings: [])
    end

    # @return [Boolean] whether the platform immutable flag is active
    def os_locked?
      assert_supported!

      if macos?
        runner.capture("ls", "-ldO", path).split.any? { _1.split(",").include?("uchg") }
      else
        runner.capture("lsattr", "-d", path).split.first.to_s.include?("i")
      end
    rescue Error, SystemCallError
      false
    end

    private

    attr_reader :platform, :root_user, :runner

    def assert_supported!
      return if macos? || linux?

      fail Unsupported, "unsupported platform: #{platform}"
    end

    def macos?
      platform.include?("darwin")
    end

    def linux?
      platform.include?("linux")
    end

    def remove_write_bits
      File.chmod(File.stat(path).mode & 0o7555, path)
    end

    def protect_macos
      runner.run("chflags", "uchg", path)
      Result.new(full: true, warnings: [])
    end

    def protect_linux
      runner.run("chattr", "+i", path)
      Result.new(full: true, warnings: [])
    end

    def restore_mode_after_failed_protect(mode)
      File.chmod(mode, path)
    rescue StandardError
      nil
    end

    def linux_warning
      escaped_path = Shellwords.escape(path)
      "delete and rename are not OS-blocked; run sudo agent-acl block edit #{escaped_path} for full protection"
    end
  end
end
