# Class AgentAcl::Guard <a id="class-AgentAcl-Guard"></a>

|  |  |
| --- | --- |
| **Inherits** | Object |
| **Defined in** | lib/agent_acl/templates/guard.rb |

Evaluates Claude Code and Codex tool payloads against a project manifest.

## Constants
### `AMBIGUOUS_SHELL_SYNTAX` <a id="constant-AMBIGUOUS_SHELL_SYNTAX"></a> <a id="AMBIGUOUS_SHELL_SYNTAX-constant"></a>
Not documented.

### `DENY_SENTENCE` <a id="constant-DENY_SENTENCE"></a> <a id="DENY_SENTENCE-constant"></a>
Not documented.

### `GIT_OUTPUT_OPTION` <a id="constant-GIT_OUTPUT_OPTION"></a> <a id="GIT_OUTPUT_OPTION-constant"></a>
Not documented.

### `HARMLESS_SHELL_BUILTINS` <a id="constant-HARMLESS_SHELL_BUILTINS"></a> <a id="HARMLESS_SHELL_BUILTINS-constant"></a>
Not documented.

### `INFRASTRUCTURE_PATHS` <a id="constant-INFRASTRUCTURE_PATHS"></a> <a id="INFRASTRUCTURE_PATHS-constant"></a>
Not documented.

### `LESS_OUTPUT_OPTION` <a id="constant-LESS_OUTPUT_OPTION"></a> <a id="LESS_OUTPUT_OPTION-constant"></a>
Not documented.

### `PATH_SCOPED_MUTATORS` <a id="constant-PATH_SCOPED_MUTATORS"></a> <a id="PATH_SCOPED_MUTATORS-constant"></a>
Not documented.

### `READ_ONLY_COMMANDS` <a id="constant-READ_ONLY_COMMANDS"></a> <a id="READ_ONLY_COMMANDS-constant"></a>
Not documented.

### `READ_ONLY_GIT_SUBCOMMANDS` <a id="constant-READ_ONLY_GIT_SUBCOMMANDS"></a> <a id="READ_ONLY_GIT_SUBCOMMANDS-constant"></a>
Not documented.

### `REDIRECTION` <a id="constant-REDIRECTION"></a> <a id="REDIRECTION-constant"></a>
Not documented.

### `SHELL_ASSIGNMENT` <a id="constant-SHELL_ASSIGNMENT"></a> <a id="SHELL_ASSIGNMENT-constant"></a>
Not documented.

### `SHELL_VARIABLE` <a id="constant-SHELL_VARIABLE"></a> <a id="SHELL_VARIABLE-constant"></a>
Not documented.

### `SPLIT_COMMANDS` <a id="constant-SPLIT_COMMANDS"></a> <a id="SPLIT_COMMANDS-constant"></a>
Not documented.

### `UNSAFE_GIT_READ_OPTIONS` <a id="constant-UNSAFE_GIT_READ_OPTIONS"></a> <a id="UNSAFE_GIT_READ_OPTIONS-constant"></a>
Not documented.

### `UNSAFE_SHELL_SYNTAX` <a id="constant-UNSAFE_SHELL_SYNTAX"></a> <a id="UNSAFE_SHELL_SYNTAX-constant"></a>
Not documented.

## Public Class Methods
### `canonical_path(path)` <a id="method-c-canonical_path"></a> <a id="canonical_path-class_method"></a>
Returns a stable absolute path even when the final path does not exist.
- **@return** [String]

### `run(input: = $stdin, output: = $stdout, root: = Dir.pwd)` <a id="method-c-run"></a> <a id="run-class_method"></a>
Runs the generated hook against an input stream.
- **@return** [Integer] hook process exit status

## Public Instance Methods
### `initialize(input:, output:, root:)` <a id="method-i-initialize"></a> <a id="initialize-instance_method"></a>
- **@return** [Guard] a new instance of Guard

### `read_only?(command)` <a id="method-i-read_only-3F"></a> <a id="read_only?-instance_method"></a>
- **@return** [Boolean] whether every shell segment is read-only

### `run()` <a id="method-i-run"></a> <a id="run-instance_method"></a>
Evaluates one hook payload and writes a denial response when required.
- **@return** [Integer] hook process exit status
