# frozen_string_literal: true

module PgTenantRls
  # The statements behind the migration DSL. Split out of Migration so the archetypes there
  # stay readable; the catalog reads these statements are decided by live in Introspection.
  module PolicyStatements
    include Introspection

    private

    # Idempotent policy write that prefers ALTER over replacement.
    #
    # ALTER POLICY can change the role list and both expressions, so when a policy of
    # this name already applies to the SAME command and is of the same kind, altering it
    # is enough — and the policy never stops existing. That matters on a live database:
    # between DROP and CREATE a table with RLS enabled has no policy at all and
    # default-denies every row, which is an outage window rather than a leak.
    #
    # A change to either forces DROP + CREATE. The documentation is explicit: "To change
    # other properties of a policy, such as the command to which it applies or whether it
    # is permissive or restrictive, the policy must be dropped and recreated." Comparing
    # the command alone was enough while permissiveness was not something an archetype
    # could state; now that it is, a permissive policy redeclared restrictive would be
    # altered in place and go on combining with OR — widening access where the
    # redeclaration asked to narrow it.
    def recreate_policy!(table, declaration, options: {}, role: nil)
      name = declaration.policy_name(table)
      predicate = resolve_predicate(declaration, options.merge(table: table))
      existing = policy_shape(table, name)

      if existing == declared_shape(declaration)
        alter_policy!(table, name, predicate, role: role)
      else
        # Only when something is actually there. The catalog has just told us whether it
        # is, so an unconditional DROP ... IF EXISTS would be a statement issued to
        # discover what we already know.
        execute "DROP POLICY #{name} ON #{quote_table_name(table)};" if existing
        create_policy!(table, declaration, predicate, role: role)
      end
    end

    # Write every policy a registered archetype declares, and nothing else. Shared by the
    # per-archetype methods and by apply_tenant_archetype!, so the two cannot disagree
    # about what an archetype consists of.
    def write_archetype_policies!(table, archetype, role: PgTenantRls.config.policy_role, **options)
      declared = Archetypes.fetch(archetype)
      resolved = declared.resolve_options(options)
      declared.policies.each do |declaration|
        recreate_policy!(table, declaration, options: resolved, role: role)
      end
    end

    # An expression is either text, written exactly as given, or something callable. Hosts
    # supply text and the gem never reads it. Its own archetypes supply callables, because
    # their predicates are built from a configuration the host writes later and from
    # tenant_id_sql, which changes the moment create_tenant_function! runs — text frozen at
    # declaration time would encode whichever of those happened to hold when the gem loaded.
    #
    # Callables are evaluated against the migration object, which is where the quoting
    # helpers and the catalog reads live.
    def resolve_predicate(declaration, options)
      { using: resolve_expression(declaration.using, options),
        check: resolve_expression(declaration.check, options) }.compact
    end

    def resolve_expression(expression, options)
      return expression unless expression.respond_to?(:call)

      instance_exec(options, &expression)
    end

    # The predicate every tenant-scoped archetype is built from: this row belongs to the
    # tenant whose context the session carries.
    def own_row_predicate(column)
      "#{quote_column_name(column)} = #{PgTenantRls.tenant_id_sql}"
    end

    # TO is omitted when no role is given: a policy without TO applies to PUBLIC, and
    # leaving the clause out keeps the dumped schema portable across hosts.
    # AS is omitted for a permissive policy, which is PostgreSQL's default: writing it out
    # would change every dumped schema this gem has already produced for no gain.
    def create_policy!(table, declaration, predicate, role: nil)
      sql = +"CREATE POLICY #{declaration.policy_name(table)} ON #{quote_table_name(table)}"
      sql << " AS RESTRICTIVE" unless declaration.permissive?
      sql << " FOR #{declaration.command}"
      sql << " TO #{role}" if role
      sql << " USING (#{predicate[:using]})" if predicate[:using]
      sql << " WITH CHECK (#{predicate[:check]})" if predicate[:check]
      execute "#{sql};"
    end

    # TO is always written out here, unlike in create_policy!: ALTER POLICY leaves every
    # unmentioned clause untouched, so omitting it would silently keep a role binding the
    # caller no longer asks for. PUBLIC is the explicit spelling of "every role".
    def alter_policy!(table, name, predicate, role: nil)
      sql = +"ALTER POLICY #{name} ON #{quote_table_name(table)} TO #{role || "PUBLIC"}"
      sql << " USING (#{predicate[:using]})" if predicate[:using]
      sql << " WITH CHECK (#{predicate[:check]})" if predicate[:check]
      execute "#{sql};"
    end

    # Remove this gem's policies for archetypes OTHER than the one just applied — what is
    # left over when a table changes archetype, e.g. public_catalog -> tenant.
    #
    # Scoped to names this gem writes: matching by name is a weak signal in general, but
    # here it errs safely. Worst case a hand-written policy that happens to be named like
    # one of ours is dropped; the alternative — dropping everything on the table — is
    # guaranteed to take the host's own policies with it every single time.
    def prune_other_archetypes!(table, archetype)
      keep = Archetypes.policy_names(table, archetype)
      ((policy_names(table) & Archetypes.all_policy_names(table)) - keep).each do |name|
        execute "DROP POLICY IF EXISTS #{quote_column_name(name)} ON #{quote_table_name(table)};"
      end
    end

    # EXISTS subquery against the gate table for create_gated_read_policy!.
    #
    # Note the gate table is read under ITS OWN policies: policy expressions run with the
    # rights of the user running the query, so a gate that is itself tenant-scoped would
    # hide other tenants' published rows and the gated table would look empty. The gate
    # has to be readable in the same context — typically public_read on the same column.
    def gated_predicate(table, gate, published_column)
      "EXISTS (SELECT 1 FROM #{quote_table_name(gate.fetch(:table))} g " \
        "WHERE g.#{quote_column_name(gate.fetch(:fk))} = #{quote_table_name(table)}.id " \
        "AND g.#{quote_column_name(published_column)})"
    end

    # ALTER TABLE has no ADD CONSTRAINT IF NOT EXISTS, so existence is checked first.
    # conrelid keeps the check on this table rather than on any same-named constraint.
    def add_constraint_unless_exists!(table, name, definition)
      execute(<<~SQL)
        DO $$ BEGIN
          IF NOT EXISTS (
            SELECT FROM pg_constraint
            WHERE conname = #{quote(name)} AND conrelid = to_regclass(#{quote(table.to_s)})
          ) THEN
            ALTER TABLE #{quote_table_name(table)} ADD CONSTRAINT #{name} #{definition};
          END IF;
        END $$;
      SQL
    end
  end
end
