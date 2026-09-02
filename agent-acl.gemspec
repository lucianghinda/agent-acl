# frozen_string_literal: true

require_relative "lib/agent_acl/version"

Gem::Specification.new do |spec|
  spec.name = "agent-acl"
  spec.version = AgentAcl::VERSION
  spec.authors = ["Lucian Ghinda"]
  spec.email = ["lucian@ghinda.com"]

  spec.summary = "Keep selected project files read-only for coding agents"
  spec.description = (
    "Adds project-local agent rules and operating-system file locks " \
      "for files a user marks as off-limits."
  )
  spec.homepage = "https://github.com/lucianghinda/agent-acl"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.2"
  spec.metadata = {
    "source_code_uri" => spec.homepage,
    "bug_tracker_uri" => "#{spec.homepage}/issues",
    "changelog_uri" => "#{spec.homepage}/blob/main/CHANGELOG.md",
    "rubygems_mfa_required" => "true"
  }

  spec.files = Dir.chdir(__dir__) do
    (
      %w[CHANGELOG.md LICENSE.txt README.md llm.txt] +
      Dir.glob("doc/**/*.{csv,md}") +
      Dir.glob("docs/**/*.md") +
      Dir.glob("exe/*") +
      Dir.glob("lib/**/*.{js,rb}")
    ).select { File.file?(_1) }.sort
  end
  spec.bindir = "exe"
  spec.executables = spec.files.grep(%r{\Aexe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_dependency "zeitwerk", "~> 2.8"

  spec.add_development_dependency "bundler", ">= 2.0", "< 5"
  spec.add_development_dependency "minitest", "~> 5.0"
  spec.add_development_dependency "rake", "~> 13.0"
  spec.add_development_dependency "rubocop", "~> 1.0"
  spec.add_development_dependency "yard", "~> 0.9"
  spec.add_development_dependency "yard-markdown", "~> 0.9"
end
