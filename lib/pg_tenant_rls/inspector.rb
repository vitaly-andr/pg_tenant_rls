# frozen_string_literal: true

require_relative "inspector/catalog"
require_relative "inspector/report"
require_relative "inspector/verdicts"
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
    extend Verdicts

    module_function

    # Full picture for every table in the perimeter. Pass tables: for an explicit list or
    # prefixes: for name prefixes — take those from Module.table_name_prefix, never a
    # literal: isolate_namespace rewrites an engine's prefix to include the host's own
    # once ActiveRecord loads, so a hardcoded prefix silently matches nothing.
    def call(connection, tables: nil, prefixes: nil, discriminator: PgTenantRls.config.discriminator)
      policies = Catalog.policies_by_relation(connection)
      columns = Catalog.discriminator_by_relation(connection, discriminator)
      unkeyed = Catalog.unkeyed_foreign_keys(connection, discriminator)
      Catalog.relations(connection, tables, prefixes).map do |row|
        describe(row, policies, columns, unkeyed, discriminator)
      end
    end

    # Compare live state against a declared manifest of { table => archetype }. Returns a
    # Report: what is wrong, and what was examined to find that out.
    #
    # The second half is not decoration. Without it "nothing is wrong" and "nothing was
    # looked at" are the same answer, which is the one failure a check cannot report about
    # itself. See Inspector::Report.
    #
    # Pass prefixes: to also catch the opposite mistake — a table that EXISTS in the
    # perimeter but is missing from the manifest. Without it a forgotten table is simply
    # never queried, and a check for "every table is declared" would be verifying itself.
    def audit(connection, manifest:, prefixes: nil, discriminator: PgTenantRls.config.discriminator,
              role: PgTenantRls.config.runtime_role)
      state = call(connection, tables: manifest.keys.map(&:to_s), discriminator: discriminator)
      merge_audits(table_audit(state, manifest),
                   perimeter_audit(connection, manifest, prefixes, discriminator),
                   membership_audit(connection, role))
    end

    def merge_audits(*parts)
      Report.new(**%i[problems checked skipped].to_h { |key| [key, parts.flat_map { |part| part[key] }] })
    end

    # audit, but raising. Use it in a deploy check or an acceptance spec.
    #
    # Raises on an audit that examined nothing, as loudly as on one that found something
    # wrong. An empty manifest with no perimeter and no role is not a passing check; it is a
    # check that did not happen, and returning success for it is how a deploy gate goes on
    # reporting health after it has stopped looking.
    def verify!(connection, manifest:, prefixes: nil, discriminator: PgTenantRls.config.discriminator,
                role: PgTenantRls.config.runtime_role)
      report = audit(connection, manifest: manifest, prefixes: prefixes,
                                 discriminator: discriminator, role: role)
      raise PgTenantRls::Error, "isolation check examined nothing:\n#{report}" if report.nothing_checked?
      raise PgTenantRls::Error, "isolation check failed:\n#{report}" unless report.clean?

      report
    end

    def table_audit(state, manifest)
      seen = state.to_h { |table| [table[:table], table] }
      checked = []
      problems = manifest.flat_map do |table, archetype|
        found = seen[table.to_s]
        next ["#{table}: table not found"] if found.nil?

        checked << "table #{table} (#{archetype})"
        problems(found, archetype.to_sym)
      end
      { problems: problems, checked: checked, skipped: [] }
    end

    # Tables inside the perimeter that the manifest never mentions. An undeclared table
    # is the failure worth catching: nobody chose an archetype for it, so nobody checked
    # whether it is isolated.
    def perimeter_audit(connection, manifest, prefixes, discriminator)
      if prefixes.nil? || prefixes.empty?
        return { problems: [], checked: [],
                 skipped: ["perimeter: no prefixes given, tables outside the manifest were not examined"] }
      end

      declared = manifest.keys.map(&:to_s)
      found = call(connection, prefixes: prefixes, discriminator: discriminator).map { |t| t[:table] }
      { problems: (found - declared).map { |t| "#{t}: in the perimeter but absent from the manifest" },
        checked: ["perimeter #{prefixes.join(", ")}"], skipped: [] }
    end

    def membership_audit(connection, role)
      if role.nil?
        return { problems: [], checked: [],
                 skipped: ["role: config.runtime_role is not set, privileged memberships were not examined"] }
      end

      { problems: membership_problems(connection, role), checked: ["role #{role}"], skipped: [] }
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
