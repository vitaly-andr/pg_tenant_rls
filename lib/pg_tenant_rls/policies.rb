# frozen_string_literal: true

module PgTenantRls
  # The access archetypes themselves — each writes a fixed set of policies whose names
  # encode which archetype produced them. Separate from Migration so that the DSL there
  # stays about operations on a table (add the column, enable RLS, apply an archetype,
  # grant) while this file is about what each archetype means.
  #
  # Every one of them takes role: from config.policy_role, which is nil by default: a
  # policy with no TO applies to PUBLIC, and that keeps the dumped schema portable.
  module Policies
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

    # Reference archetype: everyone reads, only an administrator writes.
    #
    # For shared catalogues that tenants consume but must not edit — categories, property
    # definitions, classifier values. There is no discriminator here and no tenant column:
    # the rows belong to nobody, which is the point. What RLS adds is the write side.
    #
    # Without it such a table is usually left with RLS off, and then "shared" quietly also
    # means "writable": with no policy the only thing standing between a tenant and a
    # DELETE is the GRANT, which is normally full. Shared and immutable are different
    # properties, and only the first is implied by leaving RLS off.
    #
    # `writable_when:` is a host predicate — an admin GUC, a role check, a maintenance
    # flag. The gem does not interpret it. Writes under a BYPASSRLS role (migrations,
    # seeds, imports) are unaffected, since policies do not apply to them at all.
    def create_reference_policy!(table, writable_when:, role: PgTenantRls.config.policy_role)
      recreate_policy!(table, "#{table}_reference_select", command: "SELECT", role: role,
                                                           predicate: { using: "true" })
      recreate_policy!(table, "#{table}_reference_insert", command: "INSERT", role: role,
                                                           predicate: { check: writable_when })
      recreate_policy!(table, "#{table}_reference_update", command: "UPDATE", role: role,
                                                           predicate: { using: writable_when,
                                                                        check: writable_when })
      recreate_policy!(table, "#{table}_reference_delete", command: "DELETE", role: role,
                                                           predicate: { using: writable_when })
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
  end
end
