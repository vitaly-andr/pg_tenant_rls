# frozen_string_literal: true

module PgTenantRls
  # Single registry of the access archetypes: the policies each one writes, and the helper
  # that writes them. Kept in one place because three parts of the gem need the same list —
  # the migration DSL when applying an archetype, the pruning that removes another
  # archetype's leftovers, and the inspector when checking a table against a manifest.
  module Archetypes
    # Policy name suffixes per archetype. The full name is "<table>_<suffix>".
    POLICIES = {
      tenant: %w[tenant_all],
      shared_default: %w[shared_select shared_insert shared_update shared_delete],
      public_read: %w[public_select public_insert public_update public_delete],
      gated_read: %w[gated_select gated_insert gated_update gated_delete],
      public_catalog: %w[catalog_select catalog_insert catalog_update catalog_delete],
      reference: %w[reference_select reference_insert reference_update reference_delete]
    }.freeze

    METHODS = {
      tenant: :create_tenant_policy!,
      shared_default: :create_shared_default_policy!,
      public_read: :create_public_read_policy!,
      gated_read: :create_gated_read_policy!,
      public_catalog: :create_public_catalog_policy!,
      reference: :create_reference_policy!
    }.freeze

    module_function

    def policy_names(table, archetype)
      POLICIES.fetch(archetype.to_sym).map { |suffix| "#{table}_#{suffix}" }
    end

    # Every policy name this gem could have written for the table, across all archetypes.
    def all_policy_names(table)
      POLICIES.keys.flat_map { |archetype| policy_names(table, archetype) }
    end
  end
end
