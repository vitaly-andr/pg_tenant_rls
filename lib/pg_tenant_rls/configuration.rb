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

    # Unprivileged (NOSUPERUSER/NOBYPASSRLS) runtime role. Target of GRANTs ONLY —
    # required by RoleProvisioner and grant_runtime_privileges!. It deliberately does
    # NOT reach the policy TO clause; see #policy_role.
    attr_accessor :runtime_role

    # Role bound into the policy TO clause. nil (the default) means the policies apply
    # to PUBLIC, i.e. to every non-BYPASSRLS role.
    #
    # Keep it nil unless you know you want otherwise. TO <role> adds nothing to
    # isolation (the predicate is unchanged) and costs two things: a policy that does
    # not list the connecting role simply does not apply, so with no other policy the
    # table default-denies and returns zero rows; and the dumped schema stops being
    # portable, since CREATE POLICY ... TO <role> fails to load where the role is absent.
    attr_accessor :policy_role

    def initialize
      @guc = "app.current_tenant_id"
      @discriminator = :tenant_id
      @key_type = :bigint
      @runtime_role = nil
      @policy_role = nil
    end
  end
end
