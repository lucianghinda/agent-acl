# Module AgentAcl::ProjectPath <a id="module-AgentAcl-ProjectPath"></a>

|  |  |
| --- | --- |
| **Defined in** | lib/agent_acl/project_path.rb |

Validates that managed paths remain inside the project without symlink
escapes.

## Public Class Methods
### `validate!(root, path)` <a id="method-c-validate-21"></a> <a id="validate!-class_method"></a>
- **@raise** [AgentAcl::Error] if the path escapes the project or traverses a symlink
- **@return** [String] validated absolute path
