# frozen_string_literal: true

require_relative "inspector/catalog"
require_relative "inspector/roles"

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
    # Brought in rather than delegated: these are Inspector's public surface (consumers call
    # Inspector.enforced_for_current_role? today), and a delegation line per method would be
    # the same drift risk in miniature that the archetype registry exists to remove.
    extend Roles

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
    def audit(connection, manifest:, prefixes: nil, discriminator: PgTenantRls.config.discriminator,
              role: PgTenantRls.config.runtime_role)
      report = call(connection, tables: manifest.keys.map(&:to_s), discriminator: discriminator)
      seen = report.to_h { |table| [table[:table], table] }
      declared = manifest.flat_map do |table, archetype|
        state = seen[table.to_s]
        state ? problems(state, archetype.to_sym) : ["#{table}: table not found"]
      end
      declared + undeclared_tables(connection, manifest, prefixes, discriminator) +
        membership_problems(connection, role)
    end

    # audit, but raising. Use it in a deploy check or an acceptance spec.
    def verify!(connection, manifest:, prefixes: nil, discriminator: PgTenantRls.config.discriminator,
                role: PgTenantRls.config.runtime_role)
      found = audit(connection, manifest: manifest, prefixes: prefixes,
                                discriminator: discriminator, role: role)
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

    # Expectations come from the registry, so a host archetype is verifiable on the same
    # terms as one the gem ships. Fetching also settles the unknown-archetype case: a
    # manifest naming something nobody registered is a mistake in the manifest, and saying
    # so beats reporting every policy on the table as unexpected.
    # Which registered archetype a table's policies correspond to, or nil when they
    # correspond to none. The reverse of verify!, and the question asked when there is no
    # manifest yet: an existing schema is inventoried before it can be declared.
    def identify(connection, table, discriminator: PgTenantRls.config.discriminator)
      state = call(connection, tables: [table.to_s], discriminator: discriminator).first
      return nil if state.nil?

      Archetypes.identify(state[:table], state[:policies].map { |policy| policy[:name] })
    end

    def problems(state, archetype)
      declared = Archetypes.fetch(archetype)
      found = []
      found << "#{state[:table]}: RLS is not enabled" unless state[:rls_enabled]
      found << "#{state[:table]}: RLS is not forced (the owner bypasses policies)" unless state[:rls_forced]
      found + discriminator_problems(state, declared) + policy_problems(state, declared)
    end

    # Only for an archetype that says it needs one. A shared catalogue owned by nobody has
    # no such column by design, and demanding it reported every correctly built reference
    # table as broken — the archetype is the only thing that knows, since its predicates
    # are what reference the column.
    def discriminator_problems(state, archetype)
      return [] unless archetype.discriminator?

      column = state[:discriminator]
      return ["#{state[:table]}: no discriminator column"] if column.nil?
      return [] if reads_current_tenant?(column[:default])

      ["#{state[:table]}: discriminator DEFAULT does not read #{expected_tenant_source} " \
       "(found #{column[:default].inspect})"]
    end

    # What a correct DEFAULT looks like depends on how the contour is configured. With
    # config.tenant_function set, DDL calls the function and the GUC name does not appear
    # in the DEFAULT at all — checking for the literal GUC would then fail every correctly
    # built table. Matched on the bare function name so a schema qualification present in
    # one place and absent in the other does not matter.
    def reads_current_tenant?(default)
      function = PgTenantRls.config.tenant_function
      return default.to_s.include?(function.to_s.split(".").last) if function

      default.to_s.include?(PgTenantRls.config.guc)
    end

    def expected_tenant_source
      PgTenantRls.config.tenant_function || PgTenantRls.config.guc
    end

    def policy_problems(state, archetype)
      expected = archetype.policy_names(state[:table])
      actual = state[:policies].map { |policy| policy[:name] }
      set_problems(state[:table], expected, actual) + restrictive_warnings(state)
    end

    def set_problems(table, expected, actual)
      missing = expected - actual
      found = []
      found << "#{table}: missing policies #{missing.join(", ")}" unless missing.empty?
      found + extra_problems(table, actual - expected)
    end

    # Two different failures that used to read as one line. A policy belonging to another
    # registered archetype is a switch that did not finish — the table is under two
    # archetypes at once, combining with OR. A policy belonging to no archetype at all is
    # something being enforced that no declaration accounts for, and it may equally be a
    # host override that is entirely intentional; either way it is not the same finding.
    def extra_problems(table, extra)
      foreign, unrecognised = extra.partition { |name| Archetypes.owner_of(table, name) }
      found = []
      found << "#{table}: policies of another archetype: #{attributed(table, foreign)}" unless foreign.empty?
      found << "#{table}: policies of no registered archetype: #{unrecognised.join(", ")}" unless unrecognised.empty?
      found
    end

    def attributed(table, names)
      names.map { |name| "#{name} (#{Archetypes.owner_of(table, name).name})" }.join(", ")
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
