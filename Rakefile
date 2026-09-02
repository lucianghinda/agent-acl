# frozen_string_literal: true

require "bundler/gem_tasks"
require "fileutils"
require "minitest/test_task"
require "yard"

Minitest::TestTask.create

require "rubocop/rake_task"

RuboCop::RakeTask.new

YARD::Rake::YardocTask.new do |task|
  task.before = -> { FileUtils.rm_rf(File.expand_path("doc", __dir__)) }
end

task default: %i[test rubocop]
