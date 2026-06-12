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
  spec.homepage = "https://github.com/vitaly-andr/pg_tenant_rls"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.2.0"

  spec.metadata["allowed_push_host"] = "https://rubygems.org"
  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = spec.homepage
  spec.metadata["rubygems_mfa_required"] = "true"

  # Files shipped in the gem. Resolved with Dir.glob rather than `git ls-files`
  # so the gemspec evaluates without git in the tree — required when the gem is
  # vendored as a path gem into a runtime image that has no git installed
  # (Bundler.setup re-evaluates path-source gemspecs on every boot).
  spec.files = Dir.chdir(__dir__) do
    Dir["lib/**/*", "LICENSE.txt", "README.md", "CHANGELOG.md"].select { |f| File.file?(f) }
  end
  spec.bindir = "exe"
  spec.executables = spec.files.grep(%r{\Aexe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_dependency "activerecord", ">= 7.1"
end
