# frozen_string_literal: true

module PgTenantRls
  # What the DSL asks the catalog before it writes anything. Split from PolicyStatements
  # along the seam that module's own comment described — reads on one side, statements on
  # the other — once the reads outgrew being a footnote to the writes.
  #
  # Every question here exists to avoid a statement. An ALTER with nothing to change still
  # takes an ACCESS EXCLUSIVE lock, and a DROP ... IF EXISTS still asks the database
  # something a read a moment earlier already answered. On a reconcile that runs each
  # deploy over every table, the difference is not cosmetic.
  #
  # Table identity is resolved through to_regclass rather than by bare name: pg_policies
  # exposes tablename without a schema, so filtering on the name alone conflates
  # same-named tables living in different schemas.
  #
  # Every read is select_values(...).first rather than select_value: the DSL is mixed into
  # whatever object the consumer hands it, and a hand-rolled adapter proxying a short list
  # of connection methods is a normal way to use this gem. Asking for one more method than
  # necessary breaks those callers with a NoMethodError.
  module Introspection
    # polcmd codes from pg_policy: the command a policy applies to.
    COMMAND_CODES = { "ALL" => "*", "SELECT" => "r", "INSERT" => "a",
                      "UPDATE" => "w", "DELETE" => "d" }.freeze

    private

    # The two properties ALTER POLICY cannot change, joined into one string — "*1" for a
    # permissive ALL policy, "r0" for a restrictive SELECT. nil when there is no such
    # policy; to_regclass yields NULL for an unknown table, which simply matches no row.
    #
    # Joined rather than fetched as two columns because select_values yields a single
    # column, and this runs for every policy on every reconcile: two queries for two
    # properties would be waste. The same reasoning shapes rls_flags.
    def policy_shape(table, name)
      select_values(
        "SELECT polcmd::text || polpermissive::int::text FROM pg_policy " \
        "WHERE polrelid = to_regclass(#{quote(table.to_s)}) AND polname = #{quote(name.to_s)}"
      ).first
    end

    # The same pair as a declaration states it, in the catalog's own vocabulary — which is
    # the only form in which the two can be compared.
    def declared_shape(declaration)
      "#{COMMAND_CODES.fetch(declaration.command)}#{declaration.permissive? ? 1 : 0}"
    end

    def policy_names(table)
      select_values(
        "SELECT polname FROM pg_policy WHERE polrelid = to_regclass(#{quote(table.to_s)})"
      )
    end

    # Both RLS flags in one round trip, as "<enabled><forced>" — e.g. "10" for a table
    # with row security on but not forced. nil when the table does not exist.
    def rls_flags(table)
      select_values(
        "SELECT relrowsecurity::int::text || relforcerowsecurity::int::text " \
        "FROM pg_class WHERE oid = to_regclass(#{quote(table.to_s)})"
      ).first
    end

    # Whether the table already carries the column. pg_attribute rather than
    # information_schema: a dropped column keeps its row and its number, so the check has
    # to exclude it, and system columns sit below attnum 1.
    def column_present?(table, column)
      select_values(
        "SELECT attname FROM pg_attribute " \
        "WHERE attrelid = to_regclass(#{quote(table.to_s)}) AND attname = #{quote(column.to_s)} " \
        "AND attnum > 0 AND NOT attisdropped"
      ).any?
    end

    # Schema-qualified sequence owned by the column, or nil when the column owns none.
    # Asking the catalog beats composing "<table>_id_seq": that guess breaks on a
    # non-default primary key and after a table rename, which does not rename the
    # sequence.
    def serial_sequence(table, column)
      select_values(
        "SELECT pg_get_serial_sequence(#{quote(table.to_s)}, #{quote(column.to_s)})"
      ).first
    end
  end
end
