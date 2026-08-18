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
    include Policies

    # Whether a method found on ActiveRecord::Migration came from this gem.
    #
    # Not simply `owner == Migration`: the DSL is assembled from several modules, so most of
    # its methods are owned by one of those rather than by Migration itself. Comparing against
    # Migration alone made the gem accuse itself of hijacking every helper it had split out —
    # and the warning that says so then fires on every boot of every consumer, which teaches
    # people to ignore the one message meant to be read.
    def self.own?(owner)
      owner == self || included_modules.include?(owner)
    end

    # Create (or replace) the function that DDL calls instead of inlining the GUC read,
    # and point the configuration at it.
    #
    # This exists because the GUC name is otherwise part of the schema: it is written
    # literally into every column DEFAULT and every policy predicate, and PostgreSQL has
    # no indirection for a GUC name inside an expression. Changing it then means rewriting
    # both — and a DEFAULT is baked when the migration runs, so tables created by an
    # ordinary migration keep the old name until an explicit migration fixes them. That
    # failure is not hypothetical: a stale DEFAULT stamps NULL, and the write is then
    # rejected by the very policy meant to protect it.
    #
    # With the function in place the GUC name lives in one body. Changing it is a
    # CREATE OR REPLACE; no table is touched, and two installs produce textually identical
    # schemas even when they read different GUCs.
    #
    # STABLE, not IMMUTABLE: the value depends on the session. Schema-qualified at the call
    # site, so a search_path cannot substitute another function. Run this BEFORE any DDL
    # that should reference it.
    def create_tenant_function!(name: "current_tenant_id", schema: "public")
      qualified = "#{schema}.#{name}"
      execute(<<~SQL)
        CREATE OR REPLACE FUNCTION #{qualified}() RETURNS #{PgTenantRls.config.key_type}
        LANGUAGE sql STABLE AS $$ SELECT #{PgTenantRls.guc_expression} $$;
      SQL
      PgTenantRls.config.tenant_function = qualified
    end

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
    #
    # The archetype is looked up in the registry, so one registered by a host behaves here
    # exactly as one shipped with the gem. An unknown name raises naming itself and what is
    # registered — the answer to "unknown archetype" should not be a missing method.
    def apply_tenant_archetype!(table, archetype, role: PgTenantRls.config.policy_role, **options)
      declared = Archetypes.fetch(archetype)
      ensure_discriminator_column!(table, declared, options)
      write_archetype_policies!(table, declared.name, role: role, **options)
      prune_other_archetypes!(table, declared.name)
    end

    # Add the discriminator column when the archetype needs one and the table has none.
    #
    # The archetype knows this, and it is the only thing that can: its predicates already
    # reference that column. Kept beside the caller instead, it becomes a list to remember
    # whenever an archetype is added — the engine grew four such lists and one of them then
    # disagreed with the others.
    #
    # The catalog is asked first rather than leaning on ADD COLUMN IF NOT EXISTS, for the
    # same reason enable_tenant_rls! checks its flags: an ALTER TABLE with nothing to change
    # still takes an ACCESS EXCLUSIVE lock, and this runs for every table on every reconcile.
    def ensure_discriminator_column!(table, archetype, options)
      return unless archetype.discriminator?

      column = archetype.resolve_options(options).fetch(:column)
      return if column.nil? || column_present?(table, column)

      add_tenant_column!(table, column: column, null: archetype.nullable_discriminator?)
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
