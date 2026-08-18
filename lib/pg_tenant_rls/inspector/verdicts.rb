# frozen_string_literal: true

module PgTenantRls
  module Inspector
    # The verdict on ONE table: whether it carries the archetype a manifest declares, whether
    # its discriminator reads the tenant, and what its policies amount to.
    #
    # Split from Inspector when the audit grew a second half — coverage — and the file stopped
    # being about one question. Everything here answers "is this table as declared"; nothing
    # here knows what else the audit looked at.
    module Verdicts
      # Which registered archetype a table's policies correspond to, or nil when they
      # correspond to none. The reverse of verify!, and the question asked when there is no
      # manifest yet: an existing schema is inventoried before it can be declared.
      def identify(connection, table, discriminator: PgTenantRls.config.discriminator)
        state = call(connection, tables: [table.to_s], discriminator: discriminator).first
        return nil if state.nil?

        Archetypes.identify(state[:table], state[:policies].map { |policy| policy[:name] })
      end

      # Expectations come from the registry, so a host archetype is verifiable on the same
      # terms as one the gem ships. Fetching also settles the unknown-archetype case: a
      # manifest naming something nobody registered is a mistake in the manifest, and saying
      # so beats reporting every policy on the table as unexpected.
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
    end
  end
end
