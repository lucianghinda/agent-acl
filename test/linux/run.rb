# frozen_string_literal: true

require "fileutils"
require "stringio"
require "tmpdir"

PROJECT_ROOT = File.expand_path("../..", __dir__)

unless RUBY_PLATFORM.include?("linux")
  image = "agent-acl-linux-test"
  dockerfile = File.join(__dir__, "Dockerfile")
  build = ["docker", "build", "--tag", image, "--file", dockerfile, PROJECT_ROOT]
  exit 1 unless system(*build)

  run = [
    "docker", "run", "--rm", "--cap-add", "LINUX_IMMUTABLE",
    "--volume", "#{PROJECT_ROOT}:/app:ro", "--workdir", "/app",
    image
  ]
  exit(system(*run) ? 0 : 1)
end

$LOAD_PATH.unshift(File.join(PROJECT_ROOT, "lib"))
require "agent_acl"

def check(condition, message)
  fail message unless condition
end

fail "Linux immutable integration must run as root" unless Process.euid.zero?

Dir.mktmpdir("agent-acl-linux-root") do |directory|
  File.chmod(0o755, directory)
  path = File.join(directory, "protected")
  File.write(path, "content")
  File.chmod(0o755, path)
  guard = AgentAcl::OsGuard.new(path:)

  begin
    result = guard.protect
    check(result.full, "root protection was reported as partial")
    check(guard.os_locked?, "chattr +i was not applied")

    child = fork do
      Process::GID.change_privilege(65_534)
      Process::UID.change_privilege(65_534)

      failures = [
        -> { File.write(path, "changed") },
        -> { File.delete(path) },
        -> { File.rename(path, "#{path}.moved") }
      ].count do |attempt|
        attempt.call
        false
      rescue SystemCallError
        true
      end

      begin
        AgentAcl::OsGuard.new(path:, root_user: false).unprotect(mode: 0o755)
        exit 1
      rescue AgentAcl::NeedsSudo
        exit(failures == 3 ? 0 : 1)
      end
    end

    _pid, status = Process.wait2(child)
    check(status.success?, "non-root process bypassed an immutable-file guarantee")
  ensure
    guard.unprotect(mode: 0o755) if File.exist?(path)
  end

  check((File.stat(path).mode & 0o7777) == 0o755, "allow did not restore the recorded mode")
  File.write(path, "editable")
end

Dir.mktmpdir("agent-acl-linux-user") do |directory|
  File.chown(65_534, 65_534, directory)
  child = fork do
    Process::GID.change_privilege(65_534)
    Process::UID.change_privilege(65_534)
    path = File.join(directory, "protected")
    File.write(path, "content")
    result = AgentAcl::OsGuard.new(path:, root_user: false).protect

    valid = !result.full &&
            File.stat(path).mode.nobits?(0o222) &&
            result.warnings.one? &&
            result.warnings.first.include?("delete and rename") &&
            result.warnings.first.include?("sudo agent-acl block edit")
    exit(valid ? 0 : 1)
  end

  _pid, status = Process.wait2(child)
  check(status.success?, "non-root Linux degradation was silent or incorrect")
end

Dir.mktmpdir("agent-acl-linux-cli") do |root|
  path = File.join(root, "protected")
  File.write(path, "content")
  previous_uid = ENV.fetch("SUDO_UID", nil)
  previous_gid = ENV.fetch("SUDO_GID", nil)
  ENV["SUDO_UID"] = "65534"
  ENV["SUDO_GID"] = "65534"

  begin
    error_output = StringIO.new
    status = AgentAcl::CLI.new(root:, out: StringIO.new, err: error_output).run(%w[block edit protected])
    check(status.zero?, "root CLI block failed: #{error_output.string}")
    check(AgentAcl::OsGuard.new(path:).os_locked?, "root CLI block did not apply +i")

    managed_paths = AgentAcl::CLI::MANAGED_PATHS.filter_map do |relative_path|
      candidate = File.join(root, relative_path)
      candidate if File.exist?(candidate)
    end
    check(managed_paths.all? { File.stat(_1).uid == 65_534 }, "root CLI left a root-owned managed path")
    check(managed_paths.all? { File.stat(_1).gid == 65_534 }, "root CLI left a root-group managed path")

    status = AgentAcl::CLI.new(root:, out: StringIO.new, err: error_output).run(%w[allow edit protected])
    check(status.zero?, "root CLI allow failed: #{error_output.string}")
  ensure
    AgentAcl::OsGuard.new(path:).unprotect(mode: 0o644) if File.exist?(path) && AgentAcl::OsGuard.new(path:).os_locked?
    ENV["SUDO_UID"] = previous_uid
    ENV["SUDO_GID"] = previous_gid
  end
end

puts "Linux OS guard and sudo ownership checks passed"
