# frozen_string_literal: true

require "pathname"
require "tempfile"

module AgentAcl
  # Reads and atomically writes the project-local `.agent-acl` manifest.
  class Manifest
    Entry = Data.define(:path, :mode)
    FILENAME = ".agent-acl"

    attr_reader :entries, :removed_entries, :root

    # Loads a project's manifest, skipping malformed lines with a warning.
    # @param root [String]
    # @param err [IO, nil]
    # @return [Manifest]
    def self.load(root, err: nil)
      manifest = new(root)
      return manifest unless File.file?(manifest.path)

      File.foreach(manifest.path, chomp: true).with_index(1) do |line, line_number|
        load_line(manifest, line, line_number, err)
      end

      manifest
    end

    def self.load_line(manifest, line, line_number, err)
      operation, mode, entry_path = line.split("\t", 3)
      valid = operation == "edit" && mode&.match?(/\A[0-7]{3,4}\z/) && entry_path && !entry_path.empty?
      fail ArgumentError unless valid

      manifest.add(entry_path, mode: mode.to_i(8))
    rescue ArgumentError
      err&.puts("agent-acl: skipping malformed line #{line_number} in #{FILENAME}")
    end
    private_class_method :load_line

    # @param root [String]
    def initialize(root)
      @root = File.expand_path(root)
      @entries = []
      @removed_entries = []
    end

    # @return [Boolean] whether the path has a manifest entry
    def protected?(entry_path)
      entries.any? { absolute_path(_1.path) == absolute_path(entry_path) }
    end

    # Adds a path while preserving the first recorded mode.
    # @return [Entry]
    def add(entry_path, mode:)
      relative = relative_path(entry_path)
      removed_entries.reject! { _1.path == relative }
      entries.find { _1.path == relative } || Entry.new(path: relative, mode: mode).tap { entries << _1 }
    end

    # Removes and records an existing entry for installer reconciliation.
    # @return [Entry, nil]
    def remove(entry_path)
      relative = relative_path(entry_path)
      entry = entries.find { _1.path == relative }
      entries.delete(entry).tap { removed_entries << _1 if _1 }
    end

    # Atomically persists the current entries.
    # @return [void]
    def write
      Tempfile.create([".agent-acl.", ".tmp"], root) do |file|
        entries.each { file.puts("edit\t#{format("%04o", _1.mode)}\t#{_1.path}") }
        file.flush
        file.fsync
        File.rename(file.path, path)
      end
    end

    # @return [String] absolute manifest path
    def path
      File.join(root, FILENAME)
    end

    # @return [String] absolute path for a manifest entry
    def absolute_path(entry_path)
      File.expand_path(entry_path, root)
    end

    # @return [String] project-relative path for an entry
    def relative_path_for(entry_path)
      relative_path(entry_path)
    end

    private

    def relative_path(entry_path)
      absolute = absolute_path(entry_path)
      prefix = "#{root}#{File::SEPARATOR}"
      fail ArgumentError, "path must be inside the project" unless absolute.start_with?(prefix)

      Pathname.new(absolute).relative_path_from(Pathname.new(root)).to_s
    end
  end
end
