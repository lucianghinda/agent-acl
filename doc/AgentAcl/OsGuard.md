# Class AgentAcl::OsGuard <a id="class-AgentAcl-OsGuard"></a>

|  |  |
| --- | --- |
| **Inherits** | Object |
| **Defined in** | lib/agent_acl/os_guard.rb |

Applies and removes platform file protections while preserving file modes.

## Attributes
### `path` [R] <a id="attribute-i-path"></a> <a id="path-instance_method"></a>
Returns the value of attribute path.

## Public Instance Methods
### `initialize(path:, platform: = RUBY_PLATFORM, root_user: = Process.euid.zero?, runner: = CommandRunner.new)` <a id="method-i-initialize"></a> <a id="initialize-instance_method"></a>
- **@param** `path` [String] file to protect
- **@param** `platform` [String] Ruby platform identifier
- **@param** `root_user` [Boolean] whether immutable Linux flags may be changed
- **@return** [OsGuard] a new instance of OsGuard

### `os_locked?()` <a id="method-i-os_locked-3F"></a> <a id="os_locked?-instance_method"></a>
- **@return** [Boolean] whether the platform immutable flag is active

### `protect()` <a id="method-i-protect"></a> <a id="protect-instance_method"></a>
Removes write bits and applies the platform immutable flag when available.
- **@return** [Result]

### `unprotect(mode:)` <a id="method-i-unprotect"></a> <a id="unprotect-instance_method"></a>
Removes platform protection and restores a recorded mode.
- **@param** `mode` [Integer]
- **@return** [Result]
