# frozen_string_literal: true

require "rails/railtie"

module PgTenantRls
  # Mixes the migration DSL into ActiveRecord::Migration when running under Rails.
  class Railtie < ::Rails::Railtie
    initializer "pg_tenant_rls.migration_helpers" do
      ActiveSupport.on_load(:active_record) do
        ActiveRecord::Migration.include(PgTenantRls::Migration)
      end
    end
  end
end
