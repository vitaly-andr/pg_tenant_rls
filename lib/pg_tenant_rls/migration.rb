# frozen_string_literal: true

module PgTenantRls
  # Migration DSL, mixed into ActiveRecord::Migration (via the Railtie). Parameterized
  # by PgTenantRls.config — no host/framework names are hardcoded. Policies are
  # role-agnostic by default (config.policy_role is nil, so no TO clause is written),
  # which keeps a dump of these objects portable; GRANTs (role-specific) stay with the
  # host and take config.runtime_role.
  module Migration
    include PolicyStatements
    include ForeignKeys

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
    #
    # Each ALTER is skipped when its flag is already set, and that is not micro-optimism:
    # PostgreSQL takes an ACCESS EXCLUSIVE lock even for a no-op ENABLE (verified against
    # pg_locks). The statement itself is metadata-only and finishes in milliseconds at any
    # table size, but acquiring that lock waits for every running query on the table and
    # queues new ones behind it — so on a reconcile that runs each deploy, a statement
    # with nothing to change freezes reads for as long as the slowest scan in flight.
    #
    # The two flags are independent: a table can be enabled but not forced, and skipping
    # the FORCE on the strength of the ENABLE flag alone would silently leave the owner
    # bypassing every policy. Unknown table (nil flags) falls through to the ALTERs, so
    # PostgreSQL reports the missing table rather than this quietly doing nothing.
    def enable_tenant_rls!(table, force: true)
      flags = rls_flags(table)
      execute "ALTER TABLE #{quote_table_name(table)} ENABLE ROW LEVEL SECURITY;" unless flags&.start_with?("1")
      return unless force && !flags&.end_with?("1")

      execute "ALTER TABLE #{quote_table_name(table)} FORCE ROW LEVEL SECURITY;"
    end

    def disable_tenant_rls!(table)
      execute "ALTER TABLE #{quote_table_name(table)} NO FORCE ROW LEVEL SECURITY;"
      execute "ALTER TABLE #{quote_table_name(table)} DISABLE ROW LEVEL SECURITY;"
    end

    # Bring a table to exactly one archetype, without ever leaving it unprotected.
    #
    # Prefer this over drop_tenant_policies! followed by a create_*_policy!. That pair
    # opens a window between the DROP and the CREATE in which a table with RLS enabled
    # has no policy at all and therefore default-denies every row — on a live database
    # that is not a lock, it is a wrong answer: a blocked query eventually returns the
    # truth, while a query slipping through the window returns an empty result that a
    # cache is happy to keep. Here the archetype's own policies are written first
    # (ALTER POLICY in place when they already exist), and only then are policies of
    # OTHER archetypes removed.
    #
    # Policies this gem did not write are left alone, so a host override survives a
    # reapply instead of having to be reinstated after it.
    def apply_tenant_archetype!(table, archetype, **options)
      public_send(Archetypes::METHODS.fetch(archetype.to_sym), table, **options)
      prune_other_archetypes!(table, archetype.to_sym)
    end

    # Drop EVERY policy on the table, including ones this gem did not create (a host
    # override, say). Callers that reapply an archetype afterwards must reapply such
    # policies too — this helper cannot tell them apart. See apply_tenant_archetype!
    # for the version that does not need the table to be stripped first.
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

    # Gated-catalog archetype: a row is visible iff a companion "gate" table (a separate
    # register keyed by a foreign key back to this table) has a matching row whose
    # `published_column` is true — OR the row belongs to the current tenant (so an owner
    # can see/manage their own not-yet-published rows). Writes stay owner-only, same shape
    # as public_read/public_catalog. Lets a synced catalog table (no `published` column of
    # its own — a re-sync would clobber one) gate visibility through an off-catalog register
    # instead (e.g. kub_products ← kub_publications).
    #
    #   create_gated_read_policy!(:kub_products, gate: { table: "kub_publications", fk: "kub_product_id" })
    def create_gated_read_policy!(table, gate:, published_column: :published,
                                  column: PgTenantRls.config.discriminator,
                                  role: PgTenantRls.config.policy_role)
      own = "#{quote_column_name(column)} = #{PgTenantRls.tenant_id_sql}"
      read = "(#{gated_predicate(table, gate, published_column)} OR #{own})"
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
