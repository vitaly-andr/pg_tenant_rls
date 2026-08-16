# frozen_string_literal: true

require "active_record"
require "securerandom"

# Live-database harness for the isolation specs.
#
# Two connections, and the second one is the whole point. DDL runs as the owner, but
# every isolation assertion runs as an unprivileged role: policies are inert under a
# superuser or a BYPASSRLS role, so a suite connected as the owner would pass with RLS
# switched off entirely.
module TestDatabase
  DATABASE = "pg_tenant_rls_test"
  # No "pg_" prefix: PostgreSQL reserves that namespace for role names.
  RUNTIME_ROLE = "tenant_rls_test_app"

  # Never a literal in the repository. Roles are cluster-wide objects, so this one is
  # visible from every database on the server the specs happen to run against — which may
  # well be a shared development cluster. A password published in a public gem would be a
  # standing invitation to log in there. Generated per run unless the environment pins it,
  # and reset on the role each time so a previous run's value stops working.
  RUNTIME_PASSWORD = ENV.fetch("PG_TENANT_RLS_TEST_PASSWORD") { SecureRandom.hex(16) }

  # Defaults point at the throwaway instance in docker-compose.yml, deliberately not at
  # a shared development cluster: these specs create roles and drop tables on every run,
  # and roles are cluster-wide objects rather than per-database ones. Override for CI.
  HOST = ENV.fetch("PGHOST", "localhost")
  PORT = ENV.fetch("PGPORT", "5434")
  OWNER_USER = ENV.fetch("PGUSER", "tenant_rls")
  OWNER_PASSWORD = ENV.fetch("PGPASSWORD", "tenant_rls")

  # Connection class for the unprivileged role. A separate abstract class is what keeps
  # the two connections apart — ActiveRecord pools per class, not per call.
  class RuntimeBase < ActiveRecord::Base
    self.abstract_class = true
  end

  module_function

  def available?
    return @available if defined?(@available)

    @available = begin
      setup!
      true
    rescue StandardError => e
      @error = e
      false
    end
  end

  def error_message
    "PostgreSQL unavailable at #{HOST}:#{PORT} (#{@error&.message}). " \
      "Isolation specs need a live database; set PGHOST/PGPORT/PGUSER/PGPASSWORD to point elsewhere."
  end

  def setup!
    create_database!
    connect_owner!
    create_runtime_role!
    connect_runtime!
  end

  def create_database!
    admin = PG.connect(host: HOST, port: PORT, user: OWNER_USER, password: OWNER_PASSWORD, dbname: "postgres")
    exists = admin.exec_params("SELECT 1 FROM pg_database WHERE datname = $1", [DATABASE]).ntuples.positive?
    admin.exec("CREATE DATABASE #{DATABASE}") unless exists
    admin.close
  end

  def connect_owner!
    ActiveRecord::Base.establish_connection(config(OWNER_USER, OWNER_PASSWORD))
    ActiveRecord::Base.connection.execute("SELECT 1")
  end

  # NOSUPERUSER/NOBYPASSRLS is the requirement under test, not a detail: without it the
  # policies below would never be consulted.
  def create_runtime_role!
    owner.execute(<<~SQL)
      DO $$ BEGIN
        IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '#{RUNTIME_ROLE}') THEN
          CREATE ROLE #{RUNTIME_ROLE} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
        END IF;
      END $$;
    SQL
    # Rotate on every run, so the credential only ever exists in this process.
    owner.execute("ALTER ROLE #{RUNTIME_ROLE} PASSWORD #{owner.quote(RUNTIME_PASSWORD)};")
    owner.execute("GRANT USAGE, CREATE ON SCHEMA public TO #{RUNTIME_ROLE};")
  end

  def connect_runtime!
    RuntimeBase.establish_connection(config(RUNTIME_ROLE, RUNTIME_PASSWORD))
    RuntimeBase.connection.execute("SELECT 1")
  end

  def config(user, password)
    { adapter: "postgresql", host: HOST, port: PORT.to_i, database: DATABASE,
      username: user, password: password }
  end

  def owner
    ActiveRecord::Base.connection
  end

  def runtime
    RuntimeBase.connection
  end

  # Migration DSL bound to a connection, the same shape bsl_kub uses in production: the
  # gem's helpers proxied onto a connection rather than onto ActiveRecord::Migration.
  class Runner
    include PgTenantRls::Migration

    def initialize(connection)
      @connection = connection
    end

    # The same short list Kub::Tenancy::MigrationAdapter forwards, on purpose: if the DSL
    # ever needs a method outside it, that consumer breaks and so should these specs.
    %i[execute quote_table_name quote_column_name quote select_values].each do |name|
      define_method(name) { |*args, **kwargs| @connection.public_send(name, *args, **kwargs) }
    end
  end

  def runner
    Runner.new(owner)
  end

  # Drop and recreate a table as the owner, granting the runtime role its DML rights.
  def reset_table!(name, columns)
    owner.execute("DROP TABLE IF EXISTS #{name} CASCADE;")
    owner.execute("CREATE TABLE #{name} (id bigserial PRIMARY KEY, #{columns});")
    owner.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON #{name} TO #{RUNTIME_ROLE};")
    owner.execute("GRANT USAGE, SELECT ON SEQUENCE #{name}_id_seq TO #{RUNTIME_ROLE};")
  end

  # Run a block with the tenant GUC set on the RUNTIME connection, then clear it.
  def as_tenant(tenant_id)
    runtime.execute("SELECT set_config('#{PgTenantRls.config.guc}', '#{tenant_id}', false)")
    yield
  ensure
    runtime.execute("SELECT set_config('#{PgTenantRls.config.guc}', '', false)")
  end

  def without_tenant
    runtime.execute("SELECT set_config('#{PgTenantRls.config.guc}', '', false)")
    yield
  end
end
