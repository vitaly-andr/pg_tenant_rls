# frozen_string_literal: true

module PgTenantRls
  # Host-configured contract. The gem is host-/framework-agnostic: it only knows the
  # GUC name, the discriminator column, the key type, and (for GRANTs) the runtime
  # role name. Tenant identity is supplied by the consumer via .configure.
  class Configuration
    # Session GUC that RLS policies read and Context sets. Reuse a GUC your app already
    # sets per request/job (e.g. "app.current_tenant_id").
    attr_accessor :guc

    # Discriminator column on tenant-scoped tables.
    attr_accessor :discriminator

    # SQL type of the tenant key (bigint for integer PKs; change for uuid hosts).
    attr_accessor :key_type

    # Unprivileged (NOSUPERUSER/NOBYPASSRLS) runtime role: target of GRANTs and of the
    # policy TO clause. Required for role provisioning; optional for the policies
    # themselves (a policy without TO applies to every non-BYPASS role).
    attr_accessor :runtime_role

    def initialize
      @guc = "app.current_tenant_id"
      @discriminator = :tenant_id
      @key_type = :bigint
      @runtime_role = nil
    end
  end
end
