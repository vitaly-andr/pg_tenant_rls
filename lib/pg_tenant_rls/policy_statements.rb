# frozen_string_literal: true

module PgTenantRls
  # Low-level catalog reads and policy statements behind the migration DSL. Split out of
  # Migration so the archetypes there stay readable.
  #
  # Table identity is resolved through to_regclass rather than by bare name: pg_policies
  # exposes tablename without a schema, so filtering on the name alone conflates
  # same-named tables living in different schemas.
  module PolicyStatements
    # polcmd codes from pg_policy: the command a policy applies to.
    COMMAND_CODES = { "ALL" => "*", "SELECT" => "r", "INSERT" => "a",
                      "UPDATE" => "w", "DELETE" => "d" }.freeze

    private

    # Idempotent policy write that prefers ALTER over replacement.
    #
    # ALTER POLICY can change the role list and both expressions, so when a policy of
    # this name already applies to the SAME command, altering it is enough — and the
    # policy never stops existing. That matters on a live database: between DROP and
    # CREATE a table with RLS enabled has no policy at all and default-denies every row,
    # which is an outage window rather than a leak. A command change still forces
    # DROP + CREATE, because ALTER POLICY can change neither the command nor the
    # permissive/restrictive kind.
    def recreate_policy!(table, name, command:, role: nil, predicate: {})
      if policy_command(table, name) == COMMAND_CODES.fetch(command)
        alter_policy!(table, name, role: role, predicate: predicate)
      else
        execute "DROP POLICY IF EXISTS #{name} ON #{quote_table_name(table)};"
        create_policy!(table, name, command: command, role: role, predicate: predicate)
      end
    end

    # TO is omitted when no role is given: a policy without TO applies to PUBLIC, and
    # leaving the clause out keeps the dumped schema portable across hosts.
    def create_policy!(table, name, command:, role: nil, predicate: {})
      sql = +"CREATE POLICY #{name} ON #{quote_table_name(table)} FOR #{command}"
      sql << " TO #{role}" if role
      sql << " USING (#{predicate[:using]})" if predicate[:using]
      sql << " WITH CHECK (#{predicate[:check]})" if predicate[:check]
      execute "#{sql};"
    end

    # TO is always written out here, unlike in create_policy!: ALTER POLICY leaves every
    # unmentioned clause untouched, so omitting it would silently keep a role binding the
    # caller no longer asks for. PUBLIC is the explicit spelling of "every role".
    def alter_policy!(table, name, role: nil, predicate: {})
      sql = +"ALTER POLICY #{name} ON #{quote_table_name(table)} TO #{role || "PUBLIC"}"
      sql << " USING (#{predicate[:using]})" if predicate[:using]
      sql << " WITH CHECK (#{predicate[:check]})" if predicate[:check]
      execute "#{sql};"
    end

    # polcmd of an existing policy, or nil when there is none. to_regclass yields NULL
    # for an unknown table, which simply matches no row.
    def policy_command(table, name)
      select_value(
        "SELECT polcmd FROM pg_policy " \
        "WHERE polrelid = to_regclass(#{quote(table.to_s)}) AND polname = #{quote(name.to_s)}"
      )
    end

    def policy_names(table)
      select_values(
        "SELECT polname FROM pg_policy WHERE polrelid = to_regclass(#{quote(table.to_s)})"
      )
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

    # Schema-qualified sequence owned by the column, or nil when the column owns none.
    # Asking the catalog beats composing "<table>_id_seq": that guess breaks on a
    # non-default primary key and after a table rename, which does not rename the
    # sequence.
    def serial_sequence(table, column)
      select_value(
        "SELECT pg_get_serial_sequence(#{quote(table.to_s)}, #{quote(column.to_s)})"
      )
    end
  end
end
