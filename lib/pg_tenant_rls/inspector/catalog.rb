# frozen_string_literal: true

module PgTenantRls
  module Inspector
    # Catalog reads behind Inspector. Everything here is read-only and keyed on OIDs, so
    # same-named tables in different schemas never merge.
    module Catalog
      COMMANDS = { "*" => "ALL", "r" => "SELECT", "a" => "INSERT", "w" => "UPDATE", "d" => "DELETE" }.freeze
      TRUTHY = [true, "t", "true"].freeze

      module_function

      def relations(connection, tables, prefixes)
        connection.select_all(<<~SQL).to_a
          SELECT c.oid, n.nspname AS schema, c.relname AS table, c.relrowsecurity AS rls_enabled,
                 c.relforcerowsecurity AS rls_forced, pg_get_userbyid(c.relowner) AS owner
          FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
          WHERE c.relkind IN ('r', 'p') AND n.nspname NOT IN ('pg_catalog', 'information_schema')
            AND #{relation_filter(connection, tables, prefixes)}
          ORDER BY n.nspname, c.relname
        SQL
      end

      # No perimeter given → every table that has RLS on. That is the honest default: the
      # gem cannot tell its own tables from the host's, and the host's own policies belong
      # in the picture anyway.
      def relation_filter(connection, tables, prefixes)
        if tables&.any?
          "c.relname IN (#{tables.map { |t| connection.quote(t.to_s) }.join(", ")})"
        elsif prefixes&.any?
          prefixes.map { |p| "c.relname LIKE #{connection.quote("#{p}%")}" }.join(" OR ")
        else
          "c.relrowsecurity"
        end
      end

      def policies_by_relation(connection)
        rows = connection.select_all(<<~SQL).to_a
          SELECT p.polrelid, p.polname, p.polcmd, p.polpermissive,
                 pg_get_expr(p.polqual, p.polrelid) AS qual,
                 pg_get_expr(p.polwithcheck, p.polrelid) AS with_check,
                 CASE WHEN 0 = ANY (p.polroles) THEN ARRAY['public']
                      ELSE ARRAY(SELECT rolname::text FROM pg_roles WHERE oid = ANY (p.polroles)) END AS roles
          FROM pg_policy p
        SQL
        rows.group_by { |r| r["polrelid"] }.transform_values { |rs| rs.map { |r| policy(r) } }
      end

      def policy(row)
        { name: row["polname"], command: COMMANDS.fetch(row["polcmd"], row["polcmd"]),
          permissive: cast_bool(row["polpermissive"]), roles: parse_array(row["roles"]),
          using: row["qual"], check: row["with_check"] }
      end

      def discriminator_by_relation(connection, discriminator)
        connection.select_all(<<~SQL).to_a.to_h { |r| [r["attrelid"], column(r)] }
          SELECT a.attrelid, format_type(a.atttypid, a.atttypmod) AS type, a.attnotnull,
                 pg_get_expr(d.adbin, d.adrelid) AS "default"
          FROM pg_attribute a
          LEFT JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
          WHERE a.attname = #{connection.quote(discriminator.to_s)}
            AND a.attnum > 0 AND NOT a.attisdropped
        SQL
      end

      def column(row)
        { type: row["type"], not_null: cast_bool(row["attnotnull"]), default: row["default"] }
      end

      # Foreign keys whose column list omits the discriminator. Those cross tenants
      # freely: referential integrity checks bypass row security, so the constraint sees
      # rows the policy hides. Expected under the public/shared archetypes, a hole under
      # `tenant`.
      def unkeyed_foreign_keys(connection, discriminator)
        rows = connection.select_all(<<~SQL).to_a
          SELECT c.conrelid, c.conname
          FROM pg_constraint c
          WHERE c.contype = 'f' AND NOT EXISTS (
            SELECT 1 FROM pg_attribute a
            WHERE a.attrelid = c.conrelid AND a.attnum = ANY (c.conkey)
              AND a.attname = #{connection.quote(discriminator.to_s)}
          )
        SQL
        rows.group_by { |r| r["conrelid"] }.transform_values { |rs| rs.map { |r| r["conname"] } }
      end

      def cast_bool(value)
        TRUTHY.include?(value)
      end

      def parse_array(value)
        return value if value.is_a?(Array)

        value.to_s.delete("{}").split(",")
      end
    end
  end
end
