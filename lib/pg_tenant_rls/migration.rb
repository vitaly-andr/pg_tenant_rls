# frozen_string_literal: true

module PgTenantRls
  # Migration DSL, mixed into ActiveRecord::Migration (via the Railtie). Parameterized
  # by PgTenantRls.config — no host/framework names are hardcoded. Policies are
  # role-agnostic by default (config.policy_role is nil, so no TO clause is written),
  # which keeps a dump of these objects portable; GRANTs (role-specific) stay with the
  # host and take config.runtime_role.
  module Migration
    include PolicyStatements

    # Add the discriminator column, stamped from the GUC via a DB DEFAULT, so that even
    # raw or out-of-process (e.g. Go) INSERTs that set the GUC get the right tenant id.
    # null: false by default — runtime writes always carry a tenant context. Idempotent
    # (ADD COLUMN IF NOT EXISTS), so it is safe under a reconcile/re-run.
    def add_tenant_column!(table, column: PgTenantRls.config.discriminator,
                           type: PgTenantRls.config.key_type, null: false, default_from_guc: true)
      default = default_from_guc ? "DEFAULT #{PgTenantRls.tenant_id_sql}" : ""
      not_null = null ? "" : "NOT NULL"
      execute(
        "ALTER TABLE #{quote_table_name(table)} " \
        "ADD COLUMN IF NOT EXISTS #{quote_column_name(column)} #{type} #{default} #{not_null};".squeeze(" ")
      )
    end

    # Enable RLS. FORCE makes the table owner subject to policies too (otherwise the
    # owner bypasses them), so isolation does not depend on connecting as a non-owner.
    def enable_tenant_rls!(table, force: true)
      execute "ALTER TABLE #{quote_table_name(table)} ENABLE ROW LEVEL SECURITY;"
      execute "ALTER TABLE #{quote_table_name(table)} FORCE ROW LEVEL SECURITY;" if force
    end

    def disable_tenant_rls!(table)
      execute "ALTER TABLE #{quote_table_name(table)} NO FORCE ROW LEVEL SECURITY;"
      execute "ALTER TABLE #{quote_table_name(table)} DISABLE ROW LEVEL SECURITY;"
    end

    # Drop EVERY policy on the table, including ones this gem did not create (a host
    # override, say). Callers that reapply an archetype afterwards must reapply such
    # policies too — this helper cannot tell them apart.
    def drop_tenant_policies!(table)
      policy_names(table).each do |name|
        execute "DROP POLICY IF EXISTS #{quote_column_name(name)} ON #{quote_table_name(table)};"
      end
    end

    # Tenant-scoped archetype: a row is visible/writable iff discriminator = current tenant.
    def create_tenant_policy!(table, column: PgTenantRls.config.discriminator,
                              role: PgTenantRls.config.policy_role)
      pred = "#{quote_column_name(column)} = #{PgTenantRls.tenant_id_sql}"
      recreate_policy!(table, "#{table}_tenant_all", command: "ALL", role: role,
                                                     predicate: { using: pred, check: pred })
    end

    # Shared-default archetype: each tenant sees its own rows plus global defaults
    # (discriminator IS NULL) and writes only its own. Global defaults are seeded by an
    # admin/owner role (host concern).
    def create_shared_default_policy!(table, column: PgTenantRls.config.discriminator,
                                      role: PgTenantRls.config.policy_role)
      own = "#{quote_column_name(column)} = #{PgTenantRls.tenant_id_sql}"
      read = "(#{own} OR #{quote_column_name(column)} IS NULL)"
      recreate_policy!(table, "#{table}_shared_select", command: "SELECT", role: role, predicate: { using: read })
      recreate_policy!(table, "#{table}_shared_insert", command: "INSERT", role: role, predicate: { check: own })
      recreate_policy!(table, "#{table}_shared_update", command: "UPDATE", role: role,
                                                        predicate: { using: own, check: own })
      recreate_policy!(table, "#{table}_shared_delete", command: "DELETE", role: role, predicate: { using: own })
    end

    # Public-read archetype: anyone reads PUBLISHED rows (gated on a domain boolean column)
    # plus its own; writes only its own. The row's owner is its tenant (discriminator).
    def create_public_read_policy!(table, published_column: :published,
                                   column: PgTenantRls.config.discriminator,
                                   role: PgTenantRls.config.policy_role)
      own = "#{quote_column_name(column)} = #{PgTenantRls.tenant_id_sql}"
      read = "(#{quote_column_name(published_column)} OR #{own})"
      recreate_policy!(table, "#{table}_public_select", command: "SELECT", role: role, predicate: { using: read })
      recreate_policy!(table, "#{table}_public_insert", command: "INSERT", role: role, predicate: { check: own })
      recreate_policy!(table, "#{table}_public_update", command: "UPDATE", role: role,
                                                        predicate: { using: own, check: own })
      recreate_policy!(table, "#{table}_public_delete", command: "DELETE", role: role, predicate: { using: own })
    end

    # Gated-read archetype: a row is readable iff a GATE table marks it published, or it
    # belongs to the current tenant; writes are owner-only. For a synced catalog whose publish
    # flag must NOT live on the catalog (sync owns it): the flag lives in a separate register
    # (the gate) and visibility references it — single source of truth, no denormalization.
    # `gate:` = { table:, fk:, published_column: :published }; `fk` points at this table's `key_column`.
    def create_gated_read_policy!(table, gate:, key_column: :id,
                                  column: PgTenantRls.config.discriminator,
                                  role: PgTenantRls.config.policy_role)
      own = "#{quote_column_name(column)} = #{PgTenantRls.tenant_id_sql}"
      match = "g.#{quote_column_name(gate.fetch(:fk))} = #{quote_table_name(table)}.#{quote_column_name(key_column)}"
      pub = quote_column_name(gate.fetch(:published_column, :published))
      exists = "EXISTS (SELECT 1 FROM #{quote_table_name(gate.fetch(:table))} g WHERE #{match} AND g.#{pub})"
      read = "(#{exists} OR #{own})"
      recreate_policy!(table, "#{table}_gated_select", command: "SELECT", role: role, predicate: { using: read })
      recreate_policy!(table, "#{table}_gated_insert", command: "INSERT", role: role, predicate: { check: own })
      recreate_policy!(table, "#{table}_gated_update", command: "UPDATE", role: role,
                                                       predicate: { using: own, check: own })
      recreate_policy!(table, "#{table}_gated_delete", command: "DELETE", role: role, predicate: { using: own })
    end

    # Public-catalog archetype: context-keyed reads, owner-only writes. With NO tenant
    # context set (the public storefront/marketplace) every row is visible; with a
    # tenant context set (a vendor admin or per-vendor subdomain) only the tenant's own
    # rows are visible — DB-enforced read isolation for the admin while the storefront
    # stays public. Writes are always owner-only (discriminator = current tenant), so a
    # vendor can never mutate another vendor's catalog. Unlike public_read there is no
    # published-flag gate.
    def create_public_catalog_policy!(table, column: PgTenantRls.config.discriminator,
                                      role: PgTenantRls.config.policy_role)
      own = "#{quote_column_name(column)} = #{PgTenantRls.tenant_id_sql}"
      read = "(#{PgTenantRls.tenant_id_sql} IS NULL OR #{own})"
      recreate_policy!(table, "#{table}_catalog_select", command: "SELECT", role: role, predicate: { using: read })
      recreate_policy!(table, "#{table}_catalog_insert", command: "INSERT", role: role, predicate: { check: own })
      recreate_policy!(table, "#{table}_catalog_update", command: "UPDATE", role: role,
                                                         predicate: { using: own, check: own })
      recreate_policy!(table, "#{table}_catalog_delete", command: "DELETE", role: role, predicate: { using: own })
    end

    # Cross-cutting override: a PERMISSIVE policy layered on top of an archetype.
    # PostgreSQL combines permissive policies with OR, so this widens access without
    # rewriting the archetype's predicates.
    #
    # The gem never learns what the predicate means — the host supplies it (a super-admin
    # GUC, a maintenance flag, a service role), which keeps the gem host-agnostic.
    #
    # NOTE: drop_tenant_policies! removes this along with everything else, so an override
    # must be reapplied in the same pass that reapplies the archetype, not once in a
    # separate migration.
    def create_override_policy!(table, predicate:, name: "#{table}_override_all",
                                command: "ALL", role: PgTenantRls.config.policy_role)
      recreate_policy!(table, name, command: command, role: role,
                                    predicate: { using: predicate, check: predicate })
    end

    # Composite foreign key that cannot cross tenants. Referential integrity checks
    # bypass row security (PostgreSQL, "Row Security Policies"), so a plain
    # FOREIGN KEY (parent_id) REFERENCES parent (id) happily points at another tenant's
    # row: invisible, but present — and the difference between a violation and a success
    # is an existence oracle over every id. Keying the reference on the discriminator as
    # well closes that: reaching a foreign parent would require a foreign discriminator,
    # which WITH CHECK forbids.
    #
    # Applies to the `tenant` archetype ONLY. shared_default parents carry NULL
    # discriminators (unreachable through this key), and public_read/public_catalog/
    # gated_read reference other tenants on purpose.
    def add_tenant_foreign_key!(child, parent, column:, parent_key: :id, on_delete: "RESTRICT")
      discriminator = PgTenantRls.config.discriminator
      add_tenant_unique_key!(parent, key: parent_key, discriminator: discriminator)
      cols = "#{quote_column_name(discriminator)}, #{quote_column_name(column)}"
      ref = "#{quote_column_name(discriminator)}, #{quote_column_name(parent_key)}"
      add_constraint_unless_exists!(
        child, "fk_#{child}_#{column}_tenant",
        "FOREIGN KEY (#{cols}) REFERENCES #{quote_table_name(parent)} (#{ref}) ON DELETE #{on_delete}"
      )
    end

    # UNIQUE (discriminator, key) on the parent — the constraint a composite foreign key
    # references. A primary key on `key` alone does not satisfy PostgreSQL here: the
    # reference must name a declared unique constraint over exactly these columns.
    def add_tenant_unique_key!(table, key: :id, discriminator: PgTenantRls.config.discriminator)
      cols = "#{quote_column_name(discriminator)}, #{quote_column_name(key)}"
      add_constraint_unless_exists!(table, "uq_#{table}_tenant_#{key}", "UNIQUE (#{cols})")
    end

    # sequence: :auto asks the catalog which sequence the column owns. Pass a name to
    # override, or nil to skip the sequence grant.
    def grant_runtime_privileges!(table, sequence: :auto, sequence_column: :id,
                                  role: PgTenantRls.config.runtime_role)
      raise PgTenantRls::Error, "config.runtime_role is not set" unless role

      execute "GRANT SELECT, INSERT, UPDATE, DELETE ON #{quote_table_name(table)} TO #{role};"
      seq = sequence == :auto ? serial_sequence(table, sequence_column) : quote_table_name(sequence)
      execute "GRANT USAGE, SELECT ON SEQUENCE #{seq} TO #{role};" if seq
    end
  end
end
