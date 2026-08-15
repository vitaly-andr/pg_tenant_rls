# frozen_string_literal: true

source "https://rubygems.org"

# Specify your gem's dependencies in pg_tenant_rls.gemspec
gemspec

gem "irb"
gem "rake", "~> 13.0"

# Isolation cannot be proven without a real PostgreSQL: policies are inert under a
# superuser or a BYPASSRLS role, so a suite that never connects can only check the text
# of the SQL it would have run. Development-only — the gem itself needs no driver.
gem "pg", "~> 1.5"

gem "rspec", "~> 3.0"

gem "rubocop", "~> 1.21"
