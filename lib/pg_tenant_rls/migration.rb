# frozen_string_literal: true

module PgTenantRls
  # Migration DSL, mixed into ActiveRecord::Migration (via the Railtie). Parameterized
  # by PgTenantRls.config — no host/framework names are hardcoded. Policies are
  # role-agnostic in shape (the TO clause is optional), so a dump of these objects is
  # portable; GRANTs (role-specific) stay with the host.
  module Migration
    # Add the discriminator column, stamped from the GUC via a DB DEFAULT, so that even
    # raw or out-of-process (e.g. Go) INSERTs that set the GUC get the right tenant id.
    # null: false by default — runtime writes always carry a tenant context.
    def add_tenant_column!(table, column: PgTenantRls.config.discriminator,
                           type: PgTenantRls.config.key_type, null: false, default_from_guc: true)
      default = default_from_guc ? "DEFAULT #{PgTenantRls.tenant_id_sql}" : ""
      not_null = null ? "NOT NULL" : ""
      execute(
        "ALTER TABLE #{quote_table_name(table)} " \
        "ADD COLUMN #{quote_column_name(column)} #{type} #{default} #{not_null};".squeeze(" ")
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

    def drop_tenant_policies!(table)
      select_values(
        "SELECT policyname FROM pg_policies WHERE tablename = #{quote(table.to_s)}"
      ).each do |name|
        execute "DROP POLICY IF EXISTS #{quote_column_name(name)} ON #{quote_table_name(table)};"
      end
    end

    # Tenant-scoped archetype: a row is visible/writable iff discriminator = current tenant.
    def create_tenant_policy!(table, column: PgTenantRls.config.discriminator,
                              role: PgTenantRls.config.runtime_role)
      pred = "#{quote_column_name(column)} = #{PgTenantRls.tenant_id_sql}"
      recreate_policy!(table, "#{table}_tenant_all", command: "ALL", role: role,
                                                     predicate: { using: pred, check: pred })
    end

    # Public-read / owner-write archetype (a shared catalog: everyone reads, owner writes).
    def create_public_read_owner_write_policy!(table, owner_column: :owner_tenant_id,
                                               role: PgTenantRls.config.runtime_role)
      pred = "#{quote_column_name(owner_column)} = #{PgTenantRls.tenant_id_sql}"
      recreate_policy!(table, "#{table}_public_select", command: "SELECT", role: role, predicate: { using: "true" })
      recreate_policy!(table, "#{table}_owner_insert", command: "INSERT", role: role, predicate: { check: pred })
      recreate_policy!(table, "#{table}_owner_update", command: "UPDATE", role: role,
                                                       predicate: { using: pred, check: pred })
      recreate_policy!(table, "#{table}_owner_delete", command: "DELETE", role: role, predicate: { using: pred })
    end

    def grant_runtime_privileges!(table, sequence: "#{table}_id_seq", role: PgTenantRls.config.runtime_role)
      raise PgTenantRls::Error, "config.runtime_role is not set" unless role

      execute "GRANT SELECT, INSERT, UPDATE, DELETE ON #{quote_table_name(table)} TO #{role};"
      execute "GRANT USAGE, SELECT ON SEQUENCE #{quote_table_name(sequence)} TO #{role};" if sequence
    end

    private

    # Deterministic policy name + idempotent DROP IF EXISTS -> CREATE.
    # predicate: { using: <sql>, check: <sql> } (either or both optional).
    def recreate_policy!(table, name, command:, role: nil, predicate: {})
      execute "DROP POLICY IF EXISTS #{name} ON #{quote_table_name(table)};"
      sql = +"CREATE POLICY #{name} ON #{quote_table_name(table)} FOR #{command}"
      sql << " TO #{role}" if role
      sql << " USING (#{predicate[:using]})" if predicate[:using]
      sql << " WITH CHECK (#{predicate[:check]})" if predicate[:check]
      execute "#{sql};"
    end
  end
end
