# frozen_string_literal: true

require "zeitwerk"
require_relative "agent_acl/version"

# Project-local access controls for coding agents and operating-system file writes.
module AgentAcl
  # Base error for failures reported by agent-acl.
  class Error < StandardError; end
  # Raised when Linux immutable attributes require elevated privileges.
  class NeedsSudo < Error; end
  # Raised when the current operating system cannot enforce the policy.
  class Unsupported < Error; end

  LOADER = Zeitwerk::Loader.for_gem
  LOADER.inflector.inflect("cli" => "CLI")
  LOADER.collapse(File.join(__dir__, "agent_acl", "templates"))
  LOADER.setup
  private_constant :LOADER

  class << self
    private

    def loader
      LOADER
    end
  end
end
