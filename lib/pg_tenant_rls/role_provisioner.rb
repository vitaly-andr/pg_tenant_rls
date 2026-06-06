# frozen_string_literal: true

module PgTenantRls
  # Idempotent creation of the unprivileged runtime role plus its GRANTs. Run ONLY as an
  # owner/superuser. RLS is enforced only under a NOSUPERUSER/NOBYPASSRLS role, so the
  # runtime must connect as this role for policies to take effect.
  module RoleProvisioner
    module_function

    def call(connection, role: PgTenantRls.config.runtime_role, password: nil, db_name: nil)
      raise PgTenantRls::Error, "role is required" unless role

      create_role!(connection, role: role, password: password)
      grant!(connection, role: role, db_name: db_name)
    end

    # CREATE ROLE (idempotent). Run BEFORE loading a schema that contains
    # "CREATE POLICY ... TO <role>", which requires the role to already exist.
    def create_role!(connection, role: PgTenantRls.config.runtime_role, password: nil)
      password ||= ENV.fetch("APP_DB_PASSWORD", role)
      connection.execute(<<~SQL)
        DO $$ BEGIN
          IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '#{role}') THEN
            CREATE ROLE #{role} LOGIN PASSWORD #{connection.quote(password)}
              NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
          END IF;
        END $$;
      SQL
    end

    # GRANT DML + default privileges. Run AFTER schema load: a --no-privileges dump
    # strips GRANTs, so they must be re-applied to the loaded tables (otherwise the
    # runtime role hits permission denied).
    def grant!(connection, role: PgTenantRls.config.runtime_role, db_name: nil)
      db_name ||= connection.current_database
      connection.execute(<<~SQL)
        GRANT CONNECT ON DATABASE #{connection.quote_table_name(db_name)} TO #{role};
        GRANT USAGE ON SCHEMA public TO #{role};
        GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO #{role};
        GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public TO #{role};
        ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO #{role};
        ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO #{role};
      SQL
    end
  end
end
