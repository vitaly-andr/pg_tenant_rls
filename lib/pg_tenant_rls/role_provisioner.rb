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

    # Attributes a runtime role must not have. Either one makes every policy in the database
    # inert, so a role carrying one is not an unprivileged role no matter what it is called.
    PRIVILEGED = { "10" => "SUPERUSER", "01" => "BYPASSRLS", "11" => "SUPERUSER and BYPASSRLS" }.freeze

    # CREATE ROLE (idempotent). Run BEFORE loading a schema that contains
    # "CREATE POLICY ... TO <role>", which requires the role to already exist.
    #
    # A role is a CLUSTER object, not a database one, so "it already exists" is the ordinary
    # case on any server that has ever hosted this application — another database on the same
    # server, a previous deployment, a test run. Guarding the whole statement on IF NOT EXISTS
    # therefore made this method mean "a role by this name exists" rather than "the role is as
    # declared", and a rotated password was accepted and discarded without a word. The failure
    # surfaces later and somewhere else: "password authentication failed" points at the
    # configuration, not at the provisioner that reported success.
    #
    # The password is rewritten only when one was actually declared — passed in, or in
    # APP_DB_PASSWORD. The last-resort fallback is the role's own name, a development
    # convenience, and writing that over a live credential would be a strange way to fail.
    def create_role!(connection, role: PgTenantRls.config.runtime_role, password: nil)
      declared = password || ENV.fetch("APP_DB_PASSWORD", nil)
      refuse_privileged_role!(connection, role)
      connection.execute(create_role_sql(connection, role, declared))
    end

    # An existing role that carries SUPERUSER or BYPASSRLS is refused rather than corrected.
    #
    # Correcting it is not available: verified on PostgreSQL 18.6, ALTER ROLE refuses
    # NOSUPERUSER unless the caller is a superuser and NOBYPASSRLS unless the caller has
    # BYPASSRLS — and it refuses even when the attribute is merely being re-asserted. A
    # provisioner running as a CREATEROLE owner rather than a superuser, which is a normal
    # deployment, would fail on a statement with nothing to change.
    #
    # Silence is the one thing that must not happen here. Under such a role every policy this
    # gem writes is ignored, and the isolation suite passes for the wrong reason — the most
    # expensive false green there is.
    def refuse_privileged_role!(connection, role)
      flags = connection.select_values(
        "SELECT rolsuper::int::text || rolbypassrls::int::text FROM pg_roles " \
        "WHERE rolname = #{connection.quote(role.to_s)}"
      ).first
      carried = PRIVILEGED[flags]
      return if carried.nil?

      raise PgTenantRls::Error,
            "role #{role} already exists with #{carried}, under which every policy is ignored. " \
            "Provisioning it as the runtime role would report isolation that does not exist. " \
            "Remove the attribute as a superuser, or point config.runtime_role at another role."
    end

    # One statement, so the check and the write cannot be separated by another session's
    # CREATE ROLE. The ELSE branch is where the password rotation lives; with nothing
    # declared it is a PL/pgSQL no-op rather than an absent branch, which keeps the shape of
    # the statement the same in both cases.
    def create_role_sql(connection, role, declared)
      rotate = declared ? "ALTER ROLE #{role} PASSWORD #{connection.quote(declared)}" : "NULL"
      <<~SQL
        DO $$ BEGIN
          IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '#{role}') THEN
            CREATE ROLE #{role} LOGIN PASSWORD #{connection.quote(declared || role)}
              NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
          ELSE
            #{rotate};
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
