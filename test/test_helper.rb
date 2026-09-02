# frozen_string_literal: true

$LOAD_PATH.unshift File.expand_path("../lib", __dir__)
require "agent_acl"

require "minitest/autorun"
require "fileutils"
require "stringio"
require "tmpdir"
