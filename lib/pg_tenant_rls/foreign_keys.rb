# frozen_string_literal: true

module PgTenantRls
  # Tenant-scoped referential integrity, mixed into the migration DSL.
  #
  # Separate from the policy helpers because it addresses a different hole. Policies filter
  # rows; integrity checks do not go through them at all. PostgreSQL, "Row Security
  # Policies": "Referential integrity checks, such as unique or primary key constraints and
  # foreign key references, always bypass row security to ensure that data integrity is
  # maintained."
  module ForeignKeys
    # Composite foreign key that cannot cross tenants.
    #
    # A plain FOREIGN KEY (parent_id) REFERENCES parent (id) happily points at another
    # tenant's row: invisible, but present — and the difference between a violation and a
    # success is an existence oracle over every id in the parent table. Keying the
    # reference on the discriminator as well closes it: reaching a foreign parent would
    # require a foreign discriminator, which WITH CHECK forbids.
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

    # UNIQUE (discriminator, key) — the constraint a composite foreign key references, and
    # equally the way to scope a business uniqueness rule to a tenant. A primary key on
    # `key` alone does not satisfy PostgreSQL for the reference: it must name a declared
    # unique constraint over exactly these columns.
    #
    #   add_tenant_unique_key!(:products, key: :code)  # UNIQUE (tenant_id, code)
    #
    # This writes a CONSTRAINT. A partial or conditional uniqueness rule needs an INDEX
    # instead, which constraints cannot express — write that one by hand.
    def add_tenant_unique_key!(table, key: :id, discriminator: PgTenantRls.config.discriminator)
      cols = "#{quote_column_name(discriminator)}, #{quote_column_name(key)}"
      add_constraint_unless_exists!(table, "uq_#{table}_tenant_#{key}", "UNIQUE (#{cols})")
    end
  end
end
