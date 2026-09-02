# frozen_string_literal: true

require "test_helper"
require "open3"

class OsGuardMacosIntegrationTest < Minitest::Test
  def test_real_macos_lock_blocks_changes_but_allows_read_and_execution
    skip "macOS only" unless RUBY_PLATFORM.include?("darwin")

    Dir.mktmpdir do |directory|
      path = File.join(directory, "executable")
      File.write(path, "#!/usr/bin/env ruby\nputs 'ran'\n")
      File.chmod(0o755, path)
      guard = AgentAcl::OsGuard.new(path:)
      protected = false

      begin
        result = guard.protect
        protected = true

        assert result.full
        assert_equal "#!/usr/bin/env ruby\nputs 'ran'\n", File.read(path)
        stdout, stderr, status = Open3.capture3(path)
        assert status.success?, stderr
        assert_equal "ran\n", stdout
        assert_raises(SystemCallError) { File.write(path, "changed") }
        assert_raises(SystemCallError) { File.delete(path) }
        assert_raises(SystemCallError) { File.rename(path, "#{path}.moved") }
        assert_raises(SystemCallError) { File.chmod(0o644, path) }
      ensure
        guard.unprotect(mode: 0o755) if protected && File.exist?(path)
      end

      assert_equal 0o755, File.stat(path).mode & 0o7777
      File.write(path, "editable")
      assert_equal "editable", File.read(path)
    end
  end
end
