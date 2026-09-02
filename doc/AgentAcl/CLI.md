# Class AgentAcl::CLI <a id="class-AgentAcl-CLI"></a>

|  |  |
| --- | --- |
| **Inherits** | Object |
| **Defined in** | lib/agent_acl/cli.rb |

Dispatches the agent-acl command-line interface from a project root.

## Constants
### `MANAGED_PATHS` <a id="constant-MANAGED_PATHS"></a> <a id="MANAGED_PATHS-constant"></a>
Not documented.

### `UNSUPPORTED_RULE_CHARACTERS` <a id="constant-UNSUPPORTED_RULE_CHARACTERS"></a> <a id="UNSUPPORTED_RULE_CHARACTERS-constant"></a>
Not documented.

### `USAGE` <a id="constant-USAGE"></a> <a id="USAGE-constant"></a>
Not documented.

## Public Instance Methods
### `initialize(root: = Dir.pwd, out: = $stdout, err: = $stderr, os_guard_factory: = nil, installer_factories: = nil)` <a id="method-i-initialize"></a> <a id="initialize-instance_method"></a>
- **@param** `root` [String] project root used for paths and generated configuration
- **@param** `out` [IO] normal command output
- **@param** `err` [IO] warnings and errors
- **@return** [CLI] a new instance of CLI

### `run(argv)` <a id="method-i-run"></a> <a id="run-instance_method"></a>
Runs one CLI command.
- **@param** `argv` [Array<String>] command-line arguments
- **@return** [Integer] process exit status
