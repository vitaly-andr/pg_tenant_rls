# frozen_string_literal: true

require_relative "lib/pg_tenant_rls/version"

Gem::Specification.new do |spec|
  spec.name = "pg_tenant_rls"
  spec.version = PgTenantRls::VERSION
  spec.authors = ["Vitaly Andrianov"]
  spec.email = ["vitaly.andr@gmail.com"]

  spec.summary = "PostgreSQL Row-Level-Security multitenancy toolkit for ActiveRecord."
  spec.description = "Host-agnostic PostgreSQL RLS tenancy for ActiveRecord: a transaction-scoped " \
                     "SET LOCAL context wrapper, a migration DSL for tenant and owner policies with " \
                     "FORCE RLS, and runtime-role provisioning. Parameterized by a configurable GUC."
  spec.homepage = "https://github.com/vitaly-andr/pg-tenant-rls"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.2.0"

  spec.metadata["allowed_push_host"] = "https://rubygems.org"
  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = spec.homepage
  spec.metadata["rubygems_mfa_required"] = "true"

  # Specify which files should be added to the gem when it is released.
  # The `git ls-files -z` loads the files in the RubyGem that have been added into git.
  gemspec = File.basename(__FILE__)
  spec.files = IO.popen(%w[git ls-files -z], chdir: __dir__, err: IO::NULL) do |ls|
    ls.readlines("\x0", chomp: true).reject do |f|
      f == gemspec || f.start_with?(*%w[bin/ Gemfile .gitignore .rspec spec/ .rubocop.yml])
    end
  end
  spec.bindir = "exe"
  spec.executables = spec.files.grep(%r{\Aexe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_dependency "activerecord", ">= 7.1"
end
