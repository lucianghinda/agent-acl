# frozen_string_literal: true

require "json"
require "shellwords"

module AgentAcl
  # Evaluates Claude Code and Codex tool payloads against a project manifest.
  class Guard
    ProtectedPath = Struct.new(:absolute_path, :display_path, :directory, keyword_init: true) do
      def match?(candidate)
        canonical = AgentAcl::Guard.canonical_path(candidate)
        canonical == absolute_path || File.identical?(canonical, absolute_path) ||
          (directory && canonical.start_with?("#{absolute_path}/"))
      rescue Errno::ENOENT, Errno::ENOTDIR
        false
      end
    end

    DENY_SENTENCE = "The user is not allowing changes to this file."
    INFRASTRUCTURE_PATHS = [
      [".agent-acl", false],
      [".agent-acl.d", true],
      [".claude/settings.json", false],
      [".codex/hooks.json", false],
      ["opencode.json", false]
    ].freeze
    READ_ONLY_COMMANDS = %w[
      basename cat cmp diff dirname echo file grep head less ls md5 more printf pwd readlink realpath
      rg shasum stat strings sum tail test true type wc which
    ].to_h { [_1, true] }.freeze
    READ_ONLY_GIT_SUBCOMMANDS = %w[blame diff log show status].to_h { [_1, true] }.freeze
    UNSAFE_GIT_READ_OPTIONS = %w[--ext-diff --textconv].to_h { [_1, true] }.freeze
    GIT_OUTPUT_OPTION = /\A--output(?:=|\z)/
    LESS_OUTPUT_OPTION = /\A(?:-[oO]|--(?:log-file|LOG-FILE)(?:=|\z))/
    PATH_SCOPED_MUTATORS = %w[
      agent-acl chattr chflags chmod cp dd echo find install ln mkdir mv printf rm rmdir rsync tee touch
      truncate unlink
    ].to_h { [_1, true] }.freeze
    HARMLESS_SHELL_BUILTINS = %w[cd export popd pushd unset].to_h { [_1, true] }.freeze
    SPLIT_COMMANDS = /\s*(?:&&|\|\||\||;|\n)\s*/
    REDIRECTION = /(^|[^<])>>?|[12]>>?/
    UNSAFE_SHELL_SYNTAX = /`|\$\(|[<>]|(?<!&)&(?!&)/
    AMBIGUOUS_SHELL_SYNTAX = /`|\$\(|\$["']|(?<!&)&(?!&)|[{}]/
    SHELL_VARIABLE = /\$(?:\{([A-Za-z_]\w*)\}|([A-Za-z_]\w*))/
    SHELL_ASSIGNMENT = /(?:\A|[;&|]\s*)([A-Za-z_]\w*)=(?:"([^"]*)"|'([^']*)'|([^\s;&|]+))/

    # Runs the generated hook against an input stream.
    # @return [Integer] hook process exit status
    def self.run(input: $stdin, output: $stdout, root: Dir.pwd)
      new(input: input, output: output, root: root).run
    end

    # Returns a stable absolute path even when the final path does not exist.
    # @return [String]
    def self.canonical_path(path)
      File.realpath(path)
    rescue Errno::ENOENT, Errno::ENOTDIR
      File.expand_path(path)
    end

    def initialize(input:, output:, root:)
      @input = input
      @output = output
      @root = self.class.canonical_path(root)
    end

    # Evaluates one hook payload and writes a denial response when required.
    # @return [Integer] hook process exit status
    def run
      payload = parse_payload
      hits = protected_hits(payload)
      return 0 if hits.empty?

      command = shell_command(payload) if %w[Bash bash].include?(payload["tool_name"])
      return 0 if command && read_only?(command)

      output.write(JSON.generate(deny_response(hits.first.display_path)))
      output.flush
      0
    rescue StandardError
      deny_guard_error if manifest_active?
      0
    end

    # @return [Boolean] whether every shell segment is read-only
    def read_only?(command)
      return false if command.match?(REDIRECTION) || command.match?(UNSAFE_SHELL_SYNTAX)

      simple_commands(command).all? { read_only_command?(_1) }
    end

    private

    attr_reader :input, :output, :root

    def parse_payload
      payload = JSON.parse(input.read)
      fail TypeError, "hook payload must be an object" unless payload.is_a?(Hash)

      payload
    end

    def protected_hits(payload)
      targets(payload).filter_map do |target|
        target.is_a?(ProtectedPath) ? target : protected_path_for(target)
      end.uniq(&:absolute_path)
    end

    def targets(payload)
      case payload["tool_name"]
      when "Edit", "Write", "NotebookEdit", "edit", "write", "patch"
        Array(extract_path(payload))
      when "apply_patch"
        apply_patch_targets(payload)
      when "Bash", "bash"
        shell_targets(shell_command(payload))
      else
        []
      end
    end

    def extract_path(payload)
      tool_input = payload.fetch("tool_input", {})
      path = tool_input["file_path"] || tool_input["path"]
      fail KeyError, "file tool payload has no path" unless path

      path
    end

    def apply_patch_targets(payload)
      patch = payload.fetch("tool_input", {}).values_at("command", "input", "patch", "content").compact.first
      fail KeyError, "apply_patch payload has no patch text" unless patch

      patch = patch.to_s
      parsed_targets = patch.each_line(chomp: true).filter_map do |line|
        line[/\A\*\*\* (?:Update|Delete|Add) File: (.+)\z/, 1] || line[/\A\*\*\* Move to: (.+)\z/, 1]
      end

      return parsed_targets unless parsed_targets.empty?

      mentioned_paths(patch)
    end

    def shell_command(payload)
      command = payload.fetch("tool_input", {}).values_at("command", "cmd").compact.first
      fail KeyError, "shell payload has no command" unless command

      command
    end

    def mentioned_paths(text)
      protected_paths.select do |protected_path|
        path_mentioned?(text,
                        protected_path.display_path) || path_mentioned?(text,
                                                                        protected_path.absolute_path)
      end
    end

    def shell_targets(command)
      return protected_paths if command.match?(AMBIGUOUS_SHELL_SYNTAX)

      expanded, unknown_variable = expand_shell_variables(command)
      return protected_paths if unknown_variable

      command_parts = simple_commands(expanded)
      token_groups = command_parts.map { Shellwords.shellsplit(_1) }
      return protected_paths if command_parts.zip(token_groups).any? { unbounded_effects?(*_1) }

      tokens = token_groups.flatten
      return protected_paths if mutating_git?(tokens)

      protected_paths.select { shell_path_match?(_1, expanded, tokens) }
    end

    def expand_shell_variables(command)
      variables = command.scan(SHELL_ASSIGNMENT).to_h do |name, double_quoted, single_quoted, bare|
        [name, double_quoted || single_quoted || bare || ""]
      end
      unknown = false
      expanded = command.gsub(SHELL_VARIABLE) do
        name = Regexp.last_match(1) || Regexp.last_match(2)
        variables.fetch(name) do
          unknown = true
          ""
        end
      end
      [expanded, unknown]
    end

    def shell_path_match?(protected_path, command, tokens)
      return true if path_mentioned?(command, protected_path.display_path)
      return true if path_mentioned?(command, protected_path.absolute_path)

      tokens.any? do |token|
        candidate = token.delete_prefix("(").delete_suffix(")")
        File.fnmatch?(candidate, protected_path.display_path) ||
          File.fnmatch?(File.basename(candidate), File.basename(protected_path.display_path)) ||
          shell_ancestor?(candidate, protected_path.absolute_path)
      end
    end

    def mutating_git?(tokens)
      git_index = tokens.index { File.basename(_1) == "git" }
      git_index && !READ_ONLY_GIT_SUBCOMMANDS[tokens[git_index + 1]]
    end

    def unbounded_effects?(command, words)
      return false if read_only?(command) || words.empty?
      return false if words.all? { _1.match?(/\A[A-Za-z_]\w*=/) }

      executable = File.basename(words.first)
      !HARMLESS_SHELL_BUILTINS[executable] && !PATH_SCOPED_MUTATORS[executable]
    end

    def shell_ancestor?(token, protected_absolute_path)
      candidates = [token]
      candidates << token.split("=", 2).last if token.include?("=")

      candidates.uniq.any? do |candidate|
        next false if candidate.empty? || candidate.start_with?("-")

        pattern = File.expand_path(candidate, root)
        paths = candidate.match?(/[*?\[]/) ? Dir.glob(pattern) : [pattern]
        paths.any? do |path|
          canonical = self.class.canonical_path(path)
          canonical == protected_absolute_path || same_file?(canonical, protected_absolute_path) ||
            protected_absolute_path.start_with?("#{canonical.delete_suffix("/")}/")
        end
      end
    end

    def same_file?(left, right)
      File.identical?(left, right)
    rescue Errno::ENOENT, Errno::ENOTDIR
      false
    end

    def protected_path_for(candidate)
      protected_paths.find { _1.match?(expand(candidate)) }
    end

    def protected_paths
      return @protected_paths if defined?(@protected_paths)

      manifest_paths = load_manifest
      @protected_paths = manifest_paths.empty? ? [] : manifest_paths + infrastructure_paths
    end

    def load_manifest
      manifest_path = File.join(root, ".agent-acl")
      return [] unless File.file?(manifest_path)

      File.foreach(manifest_path, chomp: true).filter_map do |line|
        next if line.empty?

        fields = line.split("\t", -1)
        operation, mode, relative_path = fields
        valid = fields.length == 3 && operation == "edit" && mode.match?(/\A[0-7]{3,4}\z/) &&
                !relative_path.empty?
        fail ArgumentError, "malformed manifest" unless valid

        build_path(relative_path)
      end
    end

    def infrastructure_paths
      INFRASTRUCTURE_PATHS.map { build_path(_1[0], directory: _1[1]) }
    end

    def build_path(display_path, directory: false)
      ProtectedPath.new(
        absolute_path: self.class.canonical_path(expand(display_path)),
        display_path: display_path,
        directory: directory
      )
    end

    def expand(path)
      File.expand_path(path, root)
    end

    def path_mentioned?(text, path)
      text.match?(%r{(?:\A|[\s"'=/])#{Regexp.escape(path)}(?:\z|[\s"'/:])})
    end

    def simple_commands(command)
      command.split(SPLIT_COMMANDS).map(&:strip).reject(&:empty?)
    end

    def read_only_command?(command)
      words = command.split
      return false if words.empty?

      executable = File.basename(words.first)
      return read_only_git?(words) if executable == "git"
      return read_only_less?(words) if executable == "less"

      READ_ONLY_COMMANDS[executable]
    end

    def read_only_git?(words)
      READ_ONLY_GIT_SUBCOMMANDS[words[1]] && words.drop(2).none? do |word|
        UNSAFE_GIT_READ_OPTIONS[word] || word.match?(GIT_OUTPUT_OPTION)
      end
    end

    def read_only_less?(words)
      words.drop(1).none? { _1.match?(LESS_OUTPUT_OPTION) }
    end

    def deny_response(path)
      {
        "hookSpecificOutput" => {
          "hookEventName" => "PreToolUse",
          "permissionDecision" => "deny",
          "permissionDecisionReason" => deny_reason(path)
        }
      }
    end

    def deny_guard_error
      response = deny_response(".agent-acl")
      reason = response.fetch("hookSpecificOutput").fetch("permissionDecisionReason")
      response.fetch("hookSpecificOutput")["permissionDecisionReason"] = "agent-acl guard error. #{reason}"
      output.write(JSON.generate(response))
      output.flush
    rescue StandardError
      nil
    end

    def manifest_active?
      manifest_path = File.join(root, ".agent-acl")
      File.file?(manifest_path) && File.size?(manifest_path)
    rescue StandardError
      false
    end

    def deny_reason(path)
      "BLOCKED by agent-acl: #{DENY_SENTENCE} This is a deliberate policy, not an error. " \
        "Do not retry, and do not work around it - no shell tricks, no scripts, no renaming, " \
        "copying, or recreating the file. If your task requires changing this file, stop and ask " \
        "the user to run: agent-acl allow edit #{path}."
    end
  end
end

exit(AgentAcl::Guard.run) if caller.empty? || File.expand_path($PROGRAM_NAME) == File.expand_path(__FILE__)
