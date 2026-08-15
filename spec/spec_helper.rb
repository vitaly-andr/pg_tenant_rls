# frozen_string_literal: true

require "pg_tenant_rls"
require "pg"
require_relative "support/database"

RSpec.configure do |config|
  # Specs tagged :database need a live PostgreSQL. When there is none they are skipped
  # with a reason rather than failing — the unit specs stay runnable anywhere, and a
  # skipped isolation suite is honest about proving nothing.
  config.before(:each, :database) do
    skip(TestDatabase.error_message) unless TestDatabase.available?
  end

  # Enable flags like --only-failures and --next-failure
  config.example_status_persistence_file_path = ".rspec_status"

  # Disable RSpec exposing methods globally on `Module` and `main`
  config.disable_monkey_patching!

  config.expect_with :rspec do |c|
    c.syntax = :expect
  end
end
