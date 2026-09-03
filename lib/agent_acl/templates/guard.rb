# frozen_string_literal: true

require "json"
require "shellwords"

module AgentAcl
  class UnanalysableCommand < StandardError
    attr_reader :display_path

    def initialize(display_path: nil, message: "shell command could not be analysed")
      @display_path = display_path
      super(message)
    end
  end
  private_constant :UnanalysableCommand

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
    UNANALYSABLE_SENTENCE = "agent-acl could not determine whether this command is safe."
    EXECUTABLE_ALLOWLIST_PATH = ".agent-acl.d/executables.allow"
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
      agent-acl chattr chflags chmod cp dd echo find install less ln mkdir mv printf rm rmdir rsync sed tee touch
      truncate unlink
    ].to_h { [_1, true] }.freeze
    HARMLESS_SHELL_BUILTINS = %w[cd export unset].to_h { [_1, true] }.freeze
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

      write_denial(deny_reason(hits.first.display_path))
      0
    rescue UnanalysableCommand => e
      write_denial(unanalysable_reason(e.display_path)) if manifest_active?
      0
    rescue StandardError => e
      deny_guard_error(e) if manifest_active?
      0
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
  end

  class Guard
    private

    def shell_targets(command)
      commands = ShellSupport.split(command)
      unanalysable = UnanalysableCommand.new if ShellSupport.nonsequential_state_change?(command)
      expanded, unanalysable = expanded_shell(commands, unanalysable)
      hits, unanalysable = analyse_shell_commands(expanded, unanalysable)
      return hits unless hits.empty?

      fail unanalysable if unanalysable

      []
    end

    def expanded_shell(commands, unanalysable)
      [expand_shell_variables(commands), unanalysable]
    rescue UnanalysableCommand => e
      [commands.join("; "), unanalysable || e]
    end

    def analyse_shell_commands(expanded, unanalysable)
      current_directory = root
      hits = []
      ShellSupport.split(expanded).each do |simple_command|
        words = ShellSupport.words(simple_command)
        targets, error = guarded_segment_targets(simple_command, words, current_directory)
        unanalysable ||= error
        hits.concat(targets)
        current_directory, error = guarded_working_directory(words, current_directory)
        unanalysable ||= error
        break if error
      end
      hits.uniq!(&:absolute_path)
      [hits, unanalysable]
    end

    def guarded_segment_targets(command, words, current_directory)
      [simple_command_targets(command, words, current_directory), nil]
    rescue UnanalysableCommand => e
      [[], e]
    end

    def guarded_working_directory(words, current_directory)
      [shell_working_directory(words, current_directory), nil]
    rescue UnanalysableCommand => e
      [current_directory, e]
    end

    def expand_shell_variables(commands)
      variables = {}
      commands.map { expand_shell_command(_1, variables) }.join("; ")
    end

    def expand_shell_command(command, variables)
      expanded, unknown = ShellSupport.expand_variables(command, variables)
      fail UnanalysableCommand.new(message: "shell command contains an unknown variable") if unknown

      words = ShellSupport.words(expanded)
      assignments = words.take_while { shell_assignment?(_1) }
      persist_shell_variables(words, assignments, variables)
      expanded
    end

    def persist_shell_variables(words, assignments, variables)
      executable_words = words.drop(assignments.length)
      if words.length == assignments.length
        variables.merge!(assignments.to_h { _1.split("=", 2) })
      elsif File.basename(executable_words.first.to_s) == "unset"
        variables.merge!(assignments.to_h { _1.split("=", 2) })
        executable_words.drop(1).each { variables.delete(_1) }
      elsif File.basename(executable_words.first.to_s) == "export"
        variables.merge!(assignments.to_h { _1.split("=", 2) })
        exported = executable_words.drop(1).select { shell_assignment?(_1) }
        variables.merge!(exported.to_h { _1.split("=", 2) })
      end
    end

    def simple_command_targets(command, words, current_directory)
      assignments = shell_assignments(words)
      words = words.drop_while { shell_assignment?(_1) }
      redirection_targets = ShellSupport.redirection_targets(command)
      redirection_hits = shell_hits(redirection_targets, current_directory, syntax: command)
      return redirection_hits unless redirection_hits.empty?

      fail_on_protected_assignments(assignments, current_directory, syntax: command)
      return [] if words.empty?

      operands = ShellSupport.path_operands(words)
      hits = protected_paths.select { shell_path_match?(_1, command, operands, current_directory) }
      return [] if read_only_executable?(words)

      executable = File.basename(words.first)
      return git_targets(command, words, hits, current_directory) if executable == "git"

      write_targets = ShellSupport.write_targets(executable, words)
      return shell_hits(write_targets, current_directory, syntax: command) if write_targets
      return hits if ShellSupport.path_scoped_mutator?(executable, words, PATH_SCOPED_MUTATORS)
      return [] if HARMLESS_SHELL_BUILTINS[executable]
      return [] if executable_allowlist[executable] && !PATH_SCOPED_MUTATORS[executable]

      ShellSupport.unknown_targets(executable, hits)
    end

    def fail_on_protected_assignments(assignments, current_directory, syntax:)
      fail UnanalysableCommand if assignments.any? { _1.start_with?("CDPATH=") }

      hits = shell_hits(assignments, current_directory, syntax: syntax)
      fail UnanalysableCommand.new(display_path: hits.first.display_path) unless hits.empty?
    end

    def shell_assignments(words)
      leading = words.take_while { shell_assignment?(_1) }
      executable_words = words.drop(leading.length)
      assignments = leading
      if File.basename(executable_words.first.to_s) == "export"
        assignments += executable_words.drop(1).select { shell_assignment?(_1) }
      end

      assignments.select { unsafe_assignment?(_1) }
    end

    def unsafe_assignment?(word)
      name = word.split("=", 2).first
      name.start_with?("GIT_TRACE") || %w[CDPATH HOME LESSHISTFILE].include?(name)
    end

    def shell_hits(targets, current_directory, syntax: nil)
      target_text = targets.join(" ")
      protected_paths.select do |protected_path|
        shell_path_match?(protected_path, target_text, targets, current_directory, syntax: syntax || target_text)
      end
    end

    def git_targets(command, words, hits, current_directory)
      return ShellSupport.unknown_targets("git", hits) unless READ_ONLY_GIT_SUBCOMMANDS[words[1]]

      output_hits = shell_hits(ShellSupport.git_output_targets(words), current_directory, syntax: command)
      return output_hits unless output_hits.empty?
      return [] unless words.drop(2).any? { UNSAFE_GIT_READ_OPTIONS[_1] }

      fail UnanalysableCommand.new(display_path: hits.first&.display_path)
    end

    def shell_path_match?(protected_path, command, tokens, current_directory, syntax: command)
      return true if current_directory == root && path_mentioned?(command, protected_path.display_path)
      return true if path_mentioned?(command, protected_path.absolute_path)

      tokens.any? do |token|
        candidate = token.delete_prefix("(").delete_suffix(")")
        expand_tilde = ShellSupport.unquoted_tilde?(syntax, candidate)
        shell_ancestor?(candidate, protected_path.absolute_path, current_directory, expand_tilde: expand_tilde)
      end
    end

    def shell_working_directory(words, current_directory)
      executable_words = words.drop_while { shell_assignment?(_1) }
      return current_directory unless File.basename(executable_words.first.to_s) == "cd"

      destination = ShellSupport.cd_destination(words)
      self.class.canonical_path(File.expand_path(destination, current_directory))
    end

    def shell_ancestor?(token, protected_absolute_path, current_directory, expand_tilde: false)
      candidates = [token]
      candidates << token.split("=", 2).last if token.include?("=")

      candidates.uniq.any? do |candidate|
        next false if candidate.empty?

        pattern = shell_pattern(candidate, current_directory, expand_tilde: expand_tilde)
        next true if File.fnmatch?(pattern, protected_absolute_path)

        paths = candidate.match?(/[*?\[]/) ? Dir.glob(pattern) : [pattern]
        paths.any? do |path|
          canonical = self.class.canonical_path(path)
          canonical == protected_absolute_path || same_file?(canonical, protected_absolute_path) ||
            protected_absolute_path.start_with?("#{canonical.delete_suffix("/")}/")
        end
      end
    end

    def shell_pattern(candidate, current_directory, expand_tilde:)
      unless expand_tilde
        literal = candidate.start_with?("~") ? "./#{candidate}" : candidate
        return File.expand_path(literal, current_directory)
      end
      fail UnanalysableCommand unless candidate == "~" || candidate.start_with?("~/")

      home = ENV.fetch("HOME", "")
      fail UnanalysableCommand if home.empty?

      File.expand_path(candidate.delete_prefix("~/").delete_prefix("~"), home)
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

    def executable_allowlist
      return @executable_allowlist if defined?(@executable_allowlist)

      @executable_allowlist = ShellSupport.allowlist(expand(EXECUTABLE_ALLOWLIST_PATH))
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
      text.match?(%r{(?:\A|[\s"'=])#{Regexp.escape(path)}(?:\z|[\s"'/:])})
    end

    def read_only_executable?(words)
      executable = File.basename(words.first)
      return read_only_git?(words) if executable == "git"
      return read_only_less?(words) if executable == "less"

      READ_ONLY_COMMANDS[executable]
    end

    def shell_assignment?(word)
      word.match?(/\A[A-Za-z_]\w*=/)
    end

    def read_only_git?(words)
      READ_ONLY_GIT_SUBCOMMANDS[words[1]] && words.drop(2).none? do |word|
        UNSAFE_GIT_READ_OPTIONS[word] || word.match?(GIT_OUTPUT_OPTION)
      end
    end

    def read_only_less?(words)
      words.drop(1).none? { _1.match?(LESS_OUTPUT_OPTION) }
    end

    def deny_response(reason)
      {
        "hookSpecificOutput" => {
          "hookEventName" => "PreToolUse",
          "permissionDecision" => "deny",
          "permissionDecisionReason" => reason
        }
      }
    end

    def write_denial(reason)
      output.write(JSON.generate(deny_response(reason)))
      output.flush
    end

    def deny_guard_error(error)
      reason = "BLOCKED by agent-acl: agent-acl guard error (#{error.class}: #{error.message}). " \
               "The guard could not evaluate this request, so it was denied while protections are active."
      write_denial(reason)
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

    def unanalysable_reason(path)
      reference = path ? " The command references protected path #{path}." : ""
      "BLOCKED by agent-acl: #{UNANALYSABLE_SENTENCE}#{reference} " \
        "The command was not run because protection is fail-closed. Do not retry or work around it."
    end
  end

  class Guard
    # Parses the shell subset needed by the generated guard without executing it.
    class ShellSupport
      ERROR_CLASS = UnanalysableCommand
      QUOTES = ["'", '"'].to_h { [_1, true] }.freeze
      SEPARATORS = ["&", "|", ";", "\n"].to_h { [_1, true] }.freeze

      def self.split(command)
        new(command).split
      end

      def self.words(command)
        Shellwords.shellsplit(command)
      rescue ArgumentError => e
        unanalysable!(e.message)
      end

      def self.redirection_targets(command)
        new(command).redirection_targets
      end

      def self.path_operands(words)
        after_options = false
        words.filter_map do |word|
          if word == "--"
            after_options = true
            next
          end

          word if after_options || !word.start_with?("-")
        end
      end

      def self.unquoted_tilde?(command, word)
        parser = new(command)
        parser.split
        unquoted = parser.send(:unquoted_tilde_words).count(word)
        return false if unquoted.zero?

        occurrences = words(command).count(word)
        fail ERROR_CLASS unless unquoted == occurrences

        true
      end

      def self.nonsequential_state_change?(command)
        parser = new(command)
        commands = parser.split
        parser.nonsequential? && commands.any? do |simple_command|
          words = ShellSupport.words(simple_command)
          assignments = words.take_while { _1.match?(/\A[A-Za-z_]\w*=/) }
          executable = File.basename(words.drop(assignments.length).first.to_s)
          assignments.length == words.length || %w[cd export unset].include?(executable)
        end
      end

      def self.expand_variables(command, variables)
        VariableExpander.new(command, variables).call
      end

      def self.allowlist(path)
        entries = File.file?(path) ? File.foreach(path, chomp: true).filter_map { allowlist_entry(_1) } : []
        entries.to_h { [_1, true] }
      end

      def self.unknown_targets(executable, hits)
        if executable == "git"
          return hits unless hits.empty?

          fail ERROR_CLASS
        end
        return [] if hits.empty?

        fail ERROR_CLASS.new(display_path: hits.first.display_path)
      end

      def self.path_scoped_mutator?(executable, words, mutators)
        return mutators[executable] unless executable == "sed"

        words.drop(1).any? { _1.match?(/\A(?:-[^-]*i|--in-place(?:=|\z))/) }
      end

      def self.write_targets(executable, words)
        case executable
        when "less"
          option_targets(words, short: %w[-o -O], long: %w[--log-file --LOG-FILE])
        when "cp", "install"
          target_directory(words) || positional_destination(words)
        when "rsync"
          positional_destination(words)
        when "dd"
          words.filter_map { _1.delete_prefix("of=") if _1.start_with?("of=") }
        end
      end

      def self.git_output_targets(words)
        option_targets(words, short: [], long: ["--output"])
      end

      def self.cd_destination(words)
        assignments = words.take_while { _1.match?(/\A[A-Za-z_]\w*=/) }
        fail ERROR_CLASS if assignments.any? { _1.start_with?("CDPATH=") }

        arguments = words.drop(assignments.length + 1)
        arguments.shift while arguments.first&.match?(/\A-[LPe@]+\z/)
        return arguments.drop(1).first || fail(ERROR_CLASS) if arguments.first == "--"

        destination = arguments.first
        fail ERROR_CLASS if !destination || destination.start_with?("-", "~") || cdpath_dependent?(destination)

        destination
      end

      def self.cdpath_dependent?(destination)
        !ENV.fetch("CDPATH", "").empty? && !destination.start_with?("/", "./", "../")
      end
      private_class_method :cdpath_dependent?

      def self.allowlist_entry(line)
        entry = line.strip
        return if entry.empty? || entry.start_with?("#")

        fail ArgumentError, "malformed executable allowlist" unless entry.match?(/\A[A-Za-z0-9][\w.+-]*\z/)

        entry
      end
      private_class_method :allowlist_entry

      def self.option_targets(words, short:, long:)
        words.take_while { _1 != "--" }.each_with_index.filter_map do |word, index|
          option = (short + long).find do |candidate|
            word == candidate || word.start_with?("#{candidate}=") ||
              (short.include?(candidate) && word.start_with?(candidate))
          end
          next unless option

          attached = word.delete_prefix(option).delete_prefix("=")
          attached.empty? ? words[index + 1] : attached
        end
      end
      private_class_method :option_targets

      def self.target_directory(words)
        targets = option_targets(words, short: ["-t"], long: ["--target-directory"])
        targets unless targets.empty?
      end
      private_class_method :target_directory

      def self.positional_destination(words)
        arguments = directional_arguments(File.basename(words.first), words.drop(1))
        [arguments.last].compact
      end
      private_class_method :positional_destination

      def self.directional_arguments(executable, arguments)
        arguments = arguments.dup
        loop do
          return arguments.drop(1) if arguments.first == "--"
          break unless arguments.first&.start_with?("-")

          consume_directional_option(executable, arguments)
        end
        arguments
      end
      private_class_method :directional_arguments

      def self.consume_directional_option(executable, arguments)
        option = arguments.first
        case executable
        when "cp"
          fail ERROR_CLASS unless option == "-p"

          arguments.shift
        when "install"
          fail ERROR_CLASS unless option == "-m" || option.match?(/\A-m.+/)

          arguments.shift
          arguments.shift if option == "-m"
        when "rsync"
          fail ERROR_CLASS unless option == "-a"

          arguments.shift
        end
      end
      private_class_method :consume_directional_option

      def self.unanalysable!(message)
        fail ERROR_CLASS.new(message: message)
      end
      private_class_method :unanalysable!

      # Expands the simple shell variables understood by the guard without executing the shell.
      class VariableExpander
        def initialize(command, variables)
          @command = command
          @variables = variables
          @expanded = String.new
          @index = 0
          @quote = nil
          @unknown = false
        end

        def call
          append_next until finished?
          [expanded, unknown]
        end

        private

        attr_reader :command, :variables, :expanded, :index, :quote, :unknown

        def append_next
          if quote_character?
            toggle_quote
          elsif escaped_character?
            append_escape
          elsif current_character == "$" && quote != "'"
            append_variable
          else
            append_character
          end
        end

        def quote_character?
          (current_character == "'" && quote != '"') || (current_character == '"' && quote != "'")
        end

        def toggle_quote
          @quote = quote == current_character ? nil : current_character
          append_character
        end

        def escaped_character?
          current_character == "\\" && quote != "'"
        end

        def append_escape
          @expanded << command[index, 2]
          @index += 2
        end

        def append_variable
          match = command[index..].match(/\A#{SHELL_VARIABLE}/)
          return append_character unless match

          name = match[1] || match[2]
          @expanded << variables.fetch(name) do
            @unknown = true
            ""
          end
          @index += match[0].length
        end

        def append_character
          @expanded << current_character
          @index += 1
        end

        def current_character
          command[index]
        end

        def finished?
          index >= command.length
        end
      end
      private_constant :VariableExpander

      def initialize(command)
        @command = command
        @commands = [String.new]
        @quote = nil
        @escaped = false
        @comment = false
        @word_start = true
        @redirection_indexes = []
        @nonsequential = false
        @tilde_indexes = []
      end

      attr_reader :nonsequential
      alias nonsequential? nonsequential

      def split
        command.each_char.with_index { |character, index| append(character, index) }
        fail ERROR_CLASS.new(message: "shell command contains an unbalanced quote") if quote || escaped

        commands.map(&:strip).reject(&:empty?)
      end

      def redirection_targets
        split
        @redirection_indexes.filter_map do |index|
          redirection_target(index)
        end
      end

      private

      attr_reader :command, :commands, :quote, :escaped

      def redirection_target(index)
        cursor = index + 1
        cursor += 1 if command[cursor] == ">"
        cursor += 1 if command[cursor] == "|"
        duplicates_descriptor = command[cursor] == "&"
        cursor += 1 if duplicates_descriptor
        target = self.class.words(command[cursor..]).first
        return if duplicates_descriptor && target&.match?(/\A(?:\d+|-)\z/)

        target
      end

      def append(character, index)
        if @comment
          append_comment(character)
          return
        end
        return append_escaped(character) if escaped
        return begin_escape if escape_start?(character)
        return append_quoted(character, index) if quote
        return @comment = true if comment_start?(character)

        fail ERROR_CLASS if active_ambiguous_syntax?(character, index)
        return begin_quote(character) if QUOTES[character]
        return append_separator(character) if separator?(character, index)

        append_literal(character, index)
      end

      def escape_start?(character)
        character == "\\" && quote != "'"
      end

      def comment_start?(character)
        character == "#" && @word_start
      end

      def append_escaped(character)
        commands.last << character
        @escaped = false
        @word_start = false
      end

      def append_comment(character)
        end_comment if character == "\n"
      end

      def begin_escape
        commands.last << "\\"
        @escaped = true
      end

      def append_quoted(character, index)
        fail ERROR_CLASS if active_ambiguous_syntax?(character, index)

        commands.last << character
        @quote = nil if character == quote
      end

      def begin_quote(character)
        commands.last << character
        @quote = character
        @word_start = false
      end

      def append_separator(character)
        @nonsequential = true if %w[| &].include?(character)
        commands << String.new
        @word_start = true
      end

      def append_literal(character, index)
        @redirection_indexes << index if output_redirection_start?(character, index)
        @tilde_indexes << index if character == "~" && @word_start
        commands.last << character
        @word_start = character.match?(/\s/)
      end

      def unquoted_tilde_words
        @tilde_indexes.filter_map { self.class.words(command[_1..]).first }
      end

      def end_comment
        commands << String.new
        @comment = false
        @word_start = true
      end

      def active_ambiguous_syntax?(character, index)
        following = command[index + 1]
        preceding = index.positive? ? command[index - 1] : nil
        return false if quote == "'"
        return true if command_substitution?(character, following) || complex_parameter_expansion?(character, index)
        return false if quote

        process_substitution?(character, following) || alternate_quote?(character, following) ||
          "{}()".include?(character) || background_operator?(character, preceding, following)
      end

      def command_substitution?(character, following)
        character == "`" || (character == "$" && following == "(")
      end

      def complex_parameter_expansion?(character, index)
        return false unless character == "$" && command[index + 1] == "{"

        !command[index..].match?(/\A\$\{[A-Za-z_]\w*\}/)
      end

      def process_substitution?(character, following)
        "<>".include?(character) && following == "("
      end

      def alternate_quote?(character, following)
        character == "$" && QUOTES[following]
      end

      def background_operator?(character, preceding, following)
        character == "&" && ![preceding, following].include?("&") && preceding != ">" && following != ">"
      end

      def output_redirection_start?(character, index)
        character == ">" && command[index - 1] != ">"
      end

      def separator?(character, index)
        return false if character == "|" && index.positive? && command[index - 1] == ">"
        return false if character == "&" && (command[index - 1] == ">" || command[index + 1] == ">")

        SEPARATORS[character]
      end
    end

    private_constant :ShellSupport
  end
end

exit(AgentAcl::Guard.run) if caller.empty? || File.expand_path($PROGRAM_NAME) == File.expand_path(__FILE__)
