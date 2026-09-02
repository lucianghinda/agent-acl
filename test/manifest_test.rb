# frozen_string_literal: true

require "test_helper"

class ManifestTest < Minitest::Test
  def test_round_trips_paths_and_original_modes
    Dir.mktmpdir do |root|
      manifest = AgentAcl::Manifest.load(root)
      manifest.add(File.join(root, "LICENSE"), mode: 0o644)
      manifest.add(File.join(root, "my notes.md"), mode: 0o755)
      manifest.write

      loaded = AgentAcl::Manifest.load(root)

      assert_equal([["LICENSE", 0o644], ["my notes.md", 0o755]],
                   loaded.entries.map { [_1.path, _1.mode] })
      assert loaded.protected?(File.join(root, "LICENSE"))
      assert loaded.protected?("my notes.md")
      refute loaded.protected?(File.join(root, "LICENSE.md"))
      assert_equal "edit\t0644\tLICENSE\nedit\t0755\tmy notes.md\n", File.read(File.join(root, ".agent-acl"))
    end
  end

  def test_add_is_idempotent_and_keeps_the_first_mode
    Dir.mktmpdir do |root|
      manifest = AgentAcl::Manifest.load(root)

      first = manifest.add("LICENSE", mode: 0o644)
      second = manifest.add(File.join(root, "LICENSE"), mode: 0o600)

      assert_same first, second
      assert_equal 0o644, second.mode
      assert_equal 1, manifest.entries.length
    end
  end

  def test_remove_returns_the_entry
    Dir.mktmpdir do |root|
      manifest = AgentAcl::Manifest.load(root)
      entry = manifest.add("LICENSE", mode: 0o644)

      assert_equal entry, manifest.remove(File.join(root, "LICENSE"))
      assert_empty manifest.entries
      assert_nil manifest.remove("LICENSE")
    end
  end

  def test_load_skips_malformed_lines_and_reports_them
    Dir.mktmpdir do |root|
      File.write(File.join(root, ".agent-acl"), "broken\nedit\t0644\tgood file\nedit\tbad\tother\n")
      errors = StringIO.new

      manifest = AgentAcl::Manifest.load(root, err: errors)

      assert_equal ["good file"], manifest.entries.map(&:path)
      assert_includes errors.string, "skipping malformed line 1"
      assert_includes errors.string, "skipping malformed line 3"
    end
  end

  def test_write_replaces_the_manifest_atomically_without_leftovers
    Dir.mktmpdir do |root|
      manifest = AgentAcl::Manifest.load(root)
      manifest.add("LICENSE", mode: 0o644)

      manifest.write
      manifest.remove("LICENSE")
      manifest.write

      assert_equal "", File.read(File.join(root, ".agent-acl"))
      assert_empty Dir.glob(File.join(root, ".agent-acl.*"))
    end
  end
end
