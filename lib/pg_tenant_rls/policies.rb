# frozen_string_literal: true

module PgTenantRls
  # The access archetypes this gem ships — each a registration made through the same door a
  # host uses, so the registry cannot drift from the archetypes it was built for.
  #
  # Separate from Migration so that the DSL there stays about operations on a table (add the
  # column, enable RLS, apply an archetype, grant) while this file is about what each
  # archetype means.
  #
  # Every one of them takes role: from config.policy_role, which is nil by default: a
  # policy with no TO applies to PUBLIC, and that keeps the dumped schema portable.
  module Policies
    # An expression is a string written verbatim, or something callable resolved against the
    # migration object when the archetype is applied. These have to be callable: the
    # discriminator's name comes from a configuration the host writes, and tenant_id_sql
    # changes the moment create_tenant_function! is called. A string frozen at declaration
    # time would encode whichever of those happened to be true when the gem loaded.
    #
    # Constants rather than literals inside each declaration, because a declaration's
    # identity includes its expressions and two lambdas with identical bodies are not equal.
    # Sharing the objects is what lets an archetype be registered twice without conflict.
    OWN_ROW = ->(o) { own_row_predicate(o[:column]) }
    OWN_OR_GLOBAL = lambda { |o|
      "(#{own_row_predicate(o[:column])} OR #{quote_column_name(o[:column])} IS NULL)"
    }
    PUBLISHED_OR_OWN = lambda { |o|
      "(#{quote_column_name(o[:published_column])} OR #{own_row_predicate(o[:column])})"
    }
    GATED_OR_OWN = lambda { |o|
      "(#{gated_predicate(o[:table], o[:gate], o[:published_column])} OR #{own_row_predicate(o[:column])})"
    }
    NO_CONTEXT_OR_OWN = lambda { |o|
      "(#{PgTenantRls.tenant_id_sql} IS NULL OR #{own_row_predicate(o[:column])})"
    }
    WRITABLE_WHEN = ->(o) { o[:writable_when] }

    class << self
      # Built once and kept. Re-registering an identical archetype is allowed, and identity
      # here includes the expression objects, so handing back the same instances is what
      # makes a second registration a no-op instead of a conflict.
      def built_ins
        @built_ins ||= [tenant_archetype, shared_default_archetype, public_read_archetype,
                        gated_read_archetype, reference_archetype, public_catalog_archetype]
      end

      def register_built_ins!
        built_ins.each { |archetype| Archetypes.register(archetype) }
      end

      private

      # Tenant-scoped archetype: a row is visible/writable iff discriminator = current tenant.
      def tenant_archetype
        Archetype.new(:tenant)
                 .policy(:tenant_all, command: "ALL", using: OWN_ROW, check: OWN_ROW)
      end

      # Shared-default archetype: each tenant sees its own rows plus global defaults
      # (discriminator IS NULL) and writes only its own. Global defaults are seeded by an
      # admin/owner role (host concern).
      def shared_default_archetype
        owner_writes(Archetype.new(:shared_default).discriminator(true, nullable: true),
                     :shared, OWN_OR_GLOBAL)
      end

      # Public-read archetype: anyone reads PUBLISHED rows (gated on a domain boolean column)
      # plus its own; writes only its own. The row's owner is its tenant (discriminator).
      def public_read_archetype
        owner_writes(Archetype.new(:public_read).option(:published_column, :published),
                     :public, PUBLISHED_OR_OWN)
      end

      # Gated-catalog archetype: a row is visible iff a companion "gate" table (a separate
      # register keyed by a foreign key back to this table) has a matching row whose
      # `published_column` is true — OR the row belongs to the current tenant (so an owner
      # can see/manage their own not-yet-published rows). Writes stay owner-only, same shape
      # as public_read/public_catalog. Lets a synced catalog table (no `published` column of
      # its own — a re-sync would clobber one) gate visibility through an off-catalog register
      # instead (e.g. kub_products <- kub_publications).
      def gated_read_archetype
        owner_writes(Archetype.new(:gated_read).discriminator(true, nullable: true)
                              .option(:published_column, :published).option(:gate, required: true),
                     :gated, GATED_OR_OWN)
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
      def reference_archetype
        Archetype.new(:reference).discriminator(false)
                 .option(:writable_when, required: true)
                 .policy(:reference_select, command: "SELECT", using: "true")
                 .policy(:reference_insert, command: "INSERT", check: WRITABLE_WHEN)
                 .policy(:reference_update, command: "UPDATE", using: WRITABLE_WHEN, check: WRITABLE_WHEN)
                 .policy(:reference_delete, command: "DELETE", using: WRITABLE_WHEN)
      end

      # Public-catalog archetype: context-keyed reads, owner-only writes. With NO tenant
      # context set (the public storefront/marketplace) every row is visible; with a
      # tenant context set (a vendor admin or per-vendor subdomain) only the tenant's own
      # rows are visible — DB-enforced read isolation for the admin while the storefront
      # stays public. Writes are always owner-only (discriminator = current tenant), so a
      # vendor can never mutate another vendor's catalog. Unlike public_read there is no
      # published-flag gate.
      def public_catalog_archetype
        owner_writes(Archetype.new(:public_catalog).discriminator(true, nullable: true),
                     :catalog, NO_CONTEXT_OR_OWN)
      end

      # The shape four of the six share: a read rule of their own, and writes restricted to
      # the row's owner. Written once because it is one rule — the read is what distinguishes
      # these archetypes, and stating the write side four times invites three of them to drift.
      def owner_writes(archetype, prefix, read)
        archetype
          .policy(:"#{prefix}_select", command: "SELECT", using: read)
          .policy(:"#{prefix}_insert", command: "INSERT", check: OWN_ROW)
          .policy(:"#{prefix}_update", command: "UPDATE", using: OWN_ROW, check: OWN_ROW)
          .policy(:"#{prefix}_delete", command: "DELETE", using: OWN_ROW)
      end
    end

    # The per-archetype entry points. Each writes its archetype's policies and nothing else —
    # no pruning, no column, no RLS flag — which is what they did before the registry existed
    # and what three consumers call today. Reaching an archetype from an unknown starting
    # state is apply_tenant_archetype!'s job, not theirs.
    def create_tenant_policy!(table, column: PgTenantRls.config.discriminator,
                              role: PgTenantRls.config.policy_role)
      write_archetype_policies!(table, :tenant, role: role, column: column)
    end

    def create_shared_default_policy!(table, column: PgTenantRls.config.discriminator,
                                      role: PgTenantRls.config.policy_role)
      write_archetype_policies!(table, :shared_default, role: role, column: column)
    end

    def create_public_read_policy!(table, published_column: :published,
                                   column: PgTenantRls.config.discriminator,
                                   role: PgTenantRls.config.policy_role)
      write_archetype_policies!(table, :public_read, role: role, column: column,
                                                     published_column: published_column)
    end

    #   create_gated_read_policy!(:kub_products, gate: { table: "kub_publications", fk: "kub_product_id" })
    def create_gated_read_policy!(table, gate:, published_column: :published,
                                  column: PgTenantRls.config.discriminator,
                                  role: PgTenantRls.config.policy_role)
      write_archetype_policies!(table, :gated_read, role: role, column: column,
                                                    published_column: published_column, gate: gate)
    end

    def create_reference_policy!(table, writable_when:, role: PgTenantRls.config.policy_role)
      write_archetype_policies!(table, :reference, role: role, writable_when: writable_when)
    end

    def create_public_catalog_policy!(table, column: PgTenantRls.config.discriminator,
                                      role: PgTenantRls.config.policy_role)
      write_archetype_policies!(table, :public_catalog, role: role, column: column)
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
      recreate_policy!(table, PolicyDeclaration.new(name: name, command: command,
                                                    using: predicate, check: predicate),
                       role: role)
    end
  end
end
