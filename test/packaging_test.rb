# frozen_string_literal: true

require "test_helper"
require "bundler"
require "open3"
require "rubygems/package"
require "rbconfig"

class PackagingTest < Minitest::Test
  EXPECTED_PACKAGED_FILES = %w[
    CHANGELOG.md
    LICENSE.txt
    README.md
    doc/AgentAcl.md
    doc/AgentAcl/CLI.md
    doc/AgentAcl/Error.md
    doc/AgentAcl/Guard.md
    doc/AgentAcl/Guard/ProtectedPath.md
    doc/AgentAcl/Installers.md
    doc/AgentAcl/Installers/Base.md
    doc/AgentAcl/Installers/ClaudeCode.md
    doc/AgentAcl/Installers/Codex.md
    doc/AgentAcl/Installers/Opencode.md
    doc/AgentAcl/Manifest.md
    doc/AgentAcl/Manifest/Entry.md
    doc/AgentAcl/NeedsSudo.md
    doc/AgentAcl/OsGuard.md
    doc/AgentAcl/OsGuard/CommandRunner.md
    doc/AgentAcl/OsGuard/Result.md
    doc/AgentAcl/ProjectPath.md
    doc/AgentAcl/Unsupported.md
    doc/CHANGELOG.md
    doc/CODE_OF_CONDUCT.md
    doc/README.md
    doc/index.csv
    docs/solutions/security-issues/prevent-filesystem-alias-guard-bypass.md
    docs/verification.md
    exe/agent-acl
    lib/agent_acl.rb
    lib/agent_acl/cli.rb
    lib/agent_acl/installers/base.rb
    lib/agent_acl/installers/claude_code.rb
    lib/agent_acl/installers/codex.rb
    lib/agent_acl/installers/opencode.rb
    lib/agent_acl/manifest.rb
    lib/agent_acl/os_guard.rb
    lib/agent_acl/project_path.rb
    lib/agent_acl/templates/guard.rb
    lib/agent_acl/templates/opencode_plugin.js
    lib/agent_acl/version.rb
    llm.txt
  ].freeze

  def test_gemspec_exposes_release_metadata_and_dependencies
    spec = gemspec

    assert_equal "agent-acl", spec.name
    assert_equal "0.1.0", spec.version.to_s
    assert_equal "Keep selected project files read-only for coding agents", spec.summary
    assert_equal "MIT", spec.license
    assert_equal "https://github.com/lucianghinda/agent-acl", spec.homepage
    assert_equal ">= 3.2", spec.required_ruby_version.to_s
    assert_equal spec.homepage, spec.metadata["source_code_uri"]
    assert_equal "#{spec.homepage}/issues", spec.metadata["bug_tracker_uri"]
    assert_equal "#{spec.homepage}/blob/main/CHANGELOG.md", spec.metadata["changelog_uri"]
    assert_equal "true", spec.metadata["rubygems_mfa_required"]
    refute spec.metadata.key?("allowed_push_host")

    runtime_dependencies = dependencies(spec, :runtime)
    assert_equal({ "zeitwerk" => "~> 2.8" }, runtime_dependencies)

    assert_equal(
      {
        "bundler" => ">= 2.0, < 5",
        "minitest" => "~> 5.0",
        "rake" => "~> 13.0",
        "rubocop" => "~> 1.0",
        "yard" => "~> 0.9",
        "yard-markdown" => "~> 0.9"
      },
      dependencies(spec, :development)
    )
  end

  def test_zeitwerk_eager_loads_the_library
    assert AgentAcl.respond_to?(:loader, true), "expected AgentAcl to expose its Zeitwerk loader privately"
    loader = AgentAcl.send(:loader)

    loader.eager_load

    assert defined?(AgentAcl::CLI)
    assert defined?(AgentAcl::Guard)
    assert defined?(AgentAcl::Installers::Opencode)
  end

  def test_gemspec_uses_its_own_version_when_the_namespace_is_preloaded
    script = <<~RUBY
      module AgentAcl
        VERSION = "9.9.9"
      end
      specification = Gem::Specification.load(#{File.join(project_root, "agent-acl.gemspec").inspect})
      exit(specification.version.to_s == "0.1.0" ? 0 : 1)
    RUBY

    _stdout, stderr, status = unbundled_capture(RbConfig.ruby, "-e", script)

    assert status.success?, stderr
  end

  def test_manifest_builds_without_git_and_contains_release_assets
    with_non_git_copy do |copy_dir|
      Dir.chdir(copy_dir) do
        spec = nil
        capture_io { spec = Gem::Specification.load("agent-acl.gemspec") }
        assert_equal EXPECTED_PACKAGED_FILES, spec.files.sort
        refute(spec.files.any? { _1.start_with?("bin/") })
        refute(spec.files.any? { _1.start_with?("test/") })
        refute_includes spec.files, "Gemfile"
        refute_includes spec.files, "Gemfile.lock"
        refute_includes spec.files, "Rakefile"

        built_gem = Gem::Package.build(spec)
        assert File.exist?(File.join(copy_dir, built_gem))
      end
    end
  end

  def test_built_gem_installs_requires_and_runs_as_an_isolated_artifact
    with_non_git_copy do |copy_dir|
      built_gem = nil
      capture_io do
        built_gem = Dir.chdir(copy_dir) do
          Gem::Package.build(Gem::Specification.load("agent-acl.gemspec"))
        end
      end
      gem_home = File.join(copy_dir, "tmp", "gems")
      FileUtils.mkdir_p(gem_home)
      copy_installed_gem(Gem::Specification.find_by_name("zeitwerk"), gem_home)
      install_gem(File.join(copy_dir, built_gem), gem_home)

      script = <<~RUBY
        gem "agent-acl"
        require "agent_acl"
        AgentAcl.send(:loader).eager_load
        abort "missing CLI" unless defined?(AgentAcl::CLI)
        abort "missing version" unless AgentAcl::VERSION == "0.1.0"
      RUBY
      _stdout, stderr, status = unbundled_capture(
        { "GEM_HOME" => gem_home, "GEM_PATH" => gem_home },
        RbConfig.ruby, "-e", script
      )
      assert status.success?, stderr

      stdout, stderr, status = unbundled_capture(
        { "GEM_HOME" => gem_home, "GEM_PATH" => gem_home },
        File.join(gem_home, "bin", "agent-acl"), "version"
      )
      assert status.success?, stderr
      assert_equal "0.1.0\n", stdout
    end
  end

  def test_bin_entry_points_are_ruby_and_console_loads_the_gem
    setup = File.read(File.expand_path("../bin/setup", __dir__))
    console = File.read(File.expand_path("../bin/console", __dir__))

    assert setup.start_with?("#!/usr/bin/env ruby\n")
    assert_includes setup, '"bundle", "install"'
    assert console.start_with?("#!/usr/bin/env ruby\n")
    assert_includes console, 'require "agent_acl"'
  end

  def test_llm_document_links_only_to_packaged_files
    linked_files = File.read(File.join(project_root, "llm.txt")).scan(%r{\]\((doc/[^)]+)\)}).flatten

    refute_empty linked_files
    linked_files.each { assert_includes gemspec.files, _1 }
  end

  private

  def project_root
    File.expand_path("..", __dir__)
  end

  def gemspec
    Gem::Specification.load(File.join(project_root, "agent-acl.gemspec"))
  end

  def dependencies(spec, type)
    spec.dependencies
        .select { _1.type == type }
        .to_h { [_1.name, _1.requirement.to_s] }
  end

  def install_gem(path, gem_home)
    _stdout, stderr, status = unbundled_capture(
      { "GEM_HOME" => gem_home, "GEM_PATH" => gem_home },
      RbConfig.ruby, "-S", "gem", "install",
      "--install-dir", gem_home, "--local", "--ignore-dependencies", "--no-document", path
    )
    assert status.success?, stderr
  end

  def unbundled_capture(*command)
    Bundler.with_unbundled_env { Open3.capture3(*command) }
  end

  def copy_installed_gem(spec, gem_home)
    gems_dir = File.join(gem_home, "gems")
    specifications_dir = File.join(gem_home, "specifications")
    FileUtils.mkdir_p(gems_dir)
    FileUtils.mkdir_p(specifications_dir)
    FileUtils.cp_r(spec.full_gem_path, File.join(gems_dir, spec.full_name))
    FileUtils.cp(spec.spec_file, File.join(specifications_dir, "#{spec.full_name}.gemspec"))
  end

  def with_non_git_copy
    Dir.mktmpdir do |dir|
      Dir.children(project_root).sort.each do |entry|
        next if entry == ".git"

        FileUtils.cp_r(File.join(project_root, entry), File.join(dir, entry))
      end
      yield dir
    end
  end
end
