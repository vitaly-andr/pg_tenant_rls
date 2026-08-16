# frozen_string_literal: true

require_relative "pg_tenant_rls/version"

# PgTenantRls — PostgreSQL Row-Level-Security multitenancy for ActiveRecord.
#
# A transaction-scoped tenant context (SET LOCAL, PgBouncer-friendly), a migration DSL
# (FORCE RLS, tenant/owner policies), and provisioning of an unprivileged runtime role.
# Everything is parameterized through PgTenantRls.configure; the gem has no notion of
# teams, configs, or any particular host model.
#
#   PgTenantRls.configure do |c|
#     c.guc           = "app.current_team_id"
#     c.discriminator = :tenant_id
#     c.key_type      = :bigint
#     c.runtime_role  = "app_runtime"
#   end
module PgTenantRls
  class Error < StandardError; end

  class << self
    def config
      @config ||= Configuration.new
    end

    def configure
      yield config
      config
    end

    def reset_config!
      @config = Configuration.new
    end

    # SQL expression for the current tenant id, as written into DDL.
    #
    # By default this inlines the GUC read, which makes the GUC name part of your schema:
    # changing it later means rewriting every column DEFAULT and every policy predicate,
    # and a DEFAULT is baked at migration time, so tables created by an ordinary migration
    # will not pick up a new name on their own.
    #
    # Set config.tenant_function (see Migration#create_tenant_function!) to write a call
    # to a SQL function instead. Then the GUC name lives in one function body: changing it
    # is a CREATE OR REPLACE, schemas of different installs match textually, and no table
    # DDL is touched.
    def tenant_id_sql
      return "#{config.tenant_function}()" if config.tenant_function

      guc_expression
    end

    # The GUC read itself, always literal. This is what the indirection function wraps,
    # so it must never route back through tenant_id_sql.
    #
    # NULL when the GUC is unset (e.g. system jobs without context) so policies
    # default-deny. missing_ok=true returns an empty string instead of raising; NULLIF
    # guards the cast (an empty string cannot be cast to bigint).
    def guc_expression
      "NULLIF(current_setting(#{quote_literal(config.guc)}, true), '')::#{config.key_type}"
    end

    def quote_literal(str)
      "'#{str.to_s.gsub("'", "''")}'"
    end
  end
end

require_relative "pg_tenant_rls/configuration"
require_relative "pg_tenant_rls/context"
require_relative "pg_tenant_rls/archetypes"
require_relative "pg_tenant_rls/policy_statements"
require_relative "pg_tenant_rls/foreign_keys"
require_relative "pg_tenant_rls/policies"
require_relative "pg_tenant_rls/migration"
require_relative "pg_tenant_rls/inspector"
require_relative "pg_tenant_rls/role_provisioner"
require_relative "pg_tenant_rls/railtie" if defined?(::Rails::Railtie)
