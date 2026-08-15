# frozen_string_literal: true

require_relative "inspector/catalog"

module PgTenantRls
  # Read-only inspection of isolation state against a LIVE database.
  #
  # Why not the schema file: a Ruby schema dump does not serialize policies at all, and a
  # SQL dump only records what was last written, not what the database holds. Worse, "the
  # table has a policy" is not a useful check — it stays true when one archetype is
  # swapped for another, and public_catalog with no tenant context shows every row.
  #
  # Why the perimeter is passed in and never guessed: this gem cannot recognize its own
  # tables. A host writing the same predicate by hand produces a byte-identical DEFAULT,
  # and a policy-name suffix is a hint rather than metadata — the name survives while its
  # predicate changes. So verify! compares against a manifest the consumer declares, and
  # call reports on whatever perimeter it is handed.
  module Inspector
    # Policy names each archetype writes, keyed by the symbol used in a manifest.
    ARCHETYPE_POLICIES = {
      tenant: %w[tenant_all],
      shared_default: %w[shared_select shared_insert shared_update shared_delete],
      public_read: %w[public_select public_insert public_update public_delete],
      gated_read: %w[gated_select gated_insert gated_update gated_delete],
      public_catalog: %w[catalog_select catalog_insert catalog_update catalog_delete]
    }.freeze

    module_function

    # Full picture for every table in the perimeter. Pass tables: for an explicit list or
    # prefixes: for name prefixes — take those from Module.table_name_prefix, never a
    # literal: isolate_namespace rewrites an engine's prefix to include the host's own
    # once ActiveRecord loads, so a hardcoded "crm_" silently matches nothing.
    def call(connection, tables: nil, prefixes: nil, discriminator: PgTenantRls.config.discriminator)
      policies = Catalog.policies_by_relation(connection)
      columns = Catalog.discriminator_by_relation(connection, discriminator)
      unkeyed = Catalog.unkeyed_foreign_keys(connection, discriminator)
      Catalog.relations(connection, tables, prefixes).map do |row|
        describe(row, policies, columns, unkeyed, discriminator)
      end
    end

    # Compare live state against a declared manifest of { table => archetype }. Returns
    # the list of problems; empty means the perimeter matches.
    #
    # Pass prefixes: to also catch the opposite mistake — a table that EXISTS in the
    # perimeter but is missing from the manifest. Without it a forgotten table is simply
    # never queried, and a check for "every table is declared" would be verifying itself.
    def audit(connection, manifest:, prefixes: nil, discriminator: PgTenantRls.config.discriminator)
      report = call(connection, tables: manifest.keys.map(&:to_s), discriminator: discriminator)
      seen = report.to_h { |table| [table[:table], table] }
      declared = manifest.flat_map do |table, archetype|
        state = seen[table.to_s]
        state ? problems(state, archetype.to_sym) : ["#{table}: table not found"]
      end
      declared + undeclared_tables(connection, manifest, prefixes, discriminator)
    end

    # audit, but raising. Use it in a deploy check or an acceptance spec.
    def verify!(connection, manifest:, prefixes: nil, discriminator: PgTenantRls.config.discriminator)
      found = audit(connection, manifest: manifest, prefixes: prefixes, discriminator: discriminator)
      raise PgTenantRls::Error, "isolation check failed:\n#{found.join("\n")}" unless found.empty?

      true
    end

    # Tables inside the perimeter that the manifest never mentions. An undeclared table
    # is the failure worth catching: nobody chose an archetype for it, so nobody checked
    # whether it is isolated.
    def undeclared_tables(connection, manifest, prefixes, discriminator)
      return [] if prefixes.nil? || prefixes.empty?

      declared = manifest.keys.map(&:to_s)
      found = call(connection, prefixes: prefixes, discriminator: discriminator).map { |t| t[:table] }
      (found - declared).map { |table| "#{table}: in the perimeter but absent from the manifest" }
    end

    # Whether the CURRENT role can be held by policies at all. Under a superuser or a
    # BYPASSRLS role every policy is inert, so an isolation test run as that role passes
    # for the wrong reason — the most expensive false green there is. Worth asserting as
    # the very first line of an isolation suite.
    #
    # Scope: this answers the ROLE-level question only (rolsuper, rolbypassrls). The
    # other way to escape policies is per-table — an owner reading its own table without
    # FORCE ROW LEVEL SECURITY — which is not a property of the role and is reported per
    # table by #call as rls_forced. Both together cover the ways enforcement can be off.
    def enforced_for_current_role?(connection)
      row = connection.select_one("SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user")
      return false if row.nil?

      !(Catalog.cast_bool(row["rolsuper"]) || Catalog.cast_bool(row["rolbypassrls"]))
    end

    def problems(state, archetype)
      found = []
      found << "#{state[:table]}: RLS is not enabled" unless state[:rls_enabled]
      found << "#{state[:table]}: RLS is not forced (the owner bypasses policies)" unless state[:rls_forced]
      found + discriminator_problems(state) + policy_problems(state, archetype)
    end

    def discriminator_problems(state)
      column = state[:discriminator]
      return ["#{state[:table]}: no discriminator column"] if column.nil?
      return [] if column[:default].to_s.include?(PgTenantRls.config.guc)

      ["#{state[:table]}: discriminator DEFAULT does not read #{PgTenantRls.config.guc} " \
       "(found #{column[:default].inspect})"]
    end

    def policy_problems(state, archetype)
      expected = ARCHETYPE_POLICIES.fetch(archetype).map { |suffix| "#{state[:table]}_#{suffix}" }
      actual = state[:policies].map { |policy| policy[:name] }
      set_problems(state[:table], expected, actual) + restrictive_warnings(state)
    end

    def set_problems(table, expected, actual)
      found = []
      missing = expected - actual
      extra = actual - expected
      found << "#{table}: missing policies #{missing.join(", ")}" unless missing.empty?
      found << "#{table}: unexpected policies #{extra.join(", ")}" unless extra.empty?
      found
    end

    # Restrictive policies combine with AND, so a single one silently narrows every
    # archetype. Worth surfacing even when the expected set matches exactly.
    def restrictive_warnings(state)
      state[:policies].reject { |policy| policy[:permissive] }
                      .map { |policy| "#{state[:table]}: policy #{policy[:name]} is RESTRICTIVE (combines with AND)" }
    end

    def describe(row, policies, columns, unkeyed, discriminator)
      oid = row["oid"]
      { schema: row["schema"], table: row["table"], oid: oid,
        rls_enabled: Catalog.cast_bool(row["rls_enabled"]), rls_forced: Catalog.cast_bool(row["rls_forced"]),
        owner: row["owner"], discriminator: columns[oid]&.merge(column: discriminator.to_s),
        policies: policies.fetch(oid, []), foreign_keys_without_discriminator: unkeyed.fetch(oid, []) }
    end
  end
end
