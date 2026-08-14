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

    # Checked here rather than at include time on purpose: Railtie initializers run
    # BEFORE the application's, so a host module that patches ActiveRecord::Migration in
    # its own initializer has not been mixed in yet and nothing would be found.
    config.after_initialize { PgTenantRls::Railtie.warn_on_hijacked_helpers }

    # A host that mixes its own DSL into ActiveRecord::Migration after this gem wins on
    # every shared method name — Ruby resolves to whichever module was included last.
    # Same names with different signatures then silently do something else, which is the
    # kind of failure that reads as working code. Warn rather than raise: an existing
    # deployment may depend on that arrangement, and booting is not the moment to argue.
    def self.warn_on_hijacked_helpers
      taken = hijacked_helpers
      return if taken.empty?

      message = taken.map { |name, owner| "  #{name} -> #{owner}" }.join("\n")
      warn("[pg_tenant_rls] these migration helpers are provided by another module:\n#{message}\n" \
           "Migrations calling them get that module's behaviour, not this gem's.")
    end

    def self.hijacked_helpers
      PgTenantRls::Migration.public_instance_methods.filter_map do |name|
        owner = ActiveRecord::Migration.instance_method(name).owner
        [name, owner] unless owner == PgTenantRls::Migration
      rescue NameError
        nil
      end
    end
  end
end
