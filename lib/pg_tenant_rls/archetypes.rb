# frozen_string_literal: true

module PgTenantRls
  # The registry of access archetypes — the single source consulted when applying one, when
  # pruning another's leftovers, and when verifying a table against a manifest.
  #
  # Single on purpose. This started as two frozen hashes, and a consumer kept a third copy of
  # the same list beside them; the copy drifted through one added archetype and took 197 of its
  # 741 examples down. A list that exists twice is a list that will disagree with itself.
  #
  # The archetypes this gem ships are registered through the same door as a host's, so the
  # mechanism cannot drift from what the gem itself provides.
  module Archetypes
    module_function

    def registry
      @registry ||= {}
    end

    # Add an archetype. Re-registering an identical definition is fine — initializers get
    # re-run, and agreement is not a conflict. A differing definition under a name already
    # taken is two components disagreeing about what that name means, which is the kind of
    # thing that otherwise surfaces as a policy nobody expected.
    def register(archetype)
      archetype.validate!
      existing = registry[archetype.name]

      if existing && existing != archetype
        raise PgTenantRls::Error,
              "archetype #{archetype.name} is already registered with a different definition. " \
              "Two components disagreeing about what an archetype means will write policies " \
              "one of them does not expect."
      end

      registry[archetype.name] = archetype
    end

    def fetch(name)
      registry.fetch(name.to_sym) do
        raise PgTenantRls::Error,
              "unknown archetype #{name.inspect}; registered: #{names.join(", ")}"
      end
    end

    def registered?(name) = registry.key?(name.to_sym)

    def names = registry.keys

    def policy_names(table, archetype)
      fetch(archetype).policy_names(table)
    end

    # Every policy name any registered archetype could write for this table — the boundary of
    # what pruning may remove. Anything outside it belongs to somebody else and is left alone.
    def all_policy_names(table)
      registry.each_value.flat_map { |archetype| archetype.policy_names(table) }
    end

    # Back to what the gem ships. For tests; not part of the contract — registration is
    # boot-time and additive, and there is no way to unregister one archetype.
    #
    # The built-ins are put back rather than left out, because they are not a starting state
    # the registry happens to have: they are the gem's own archetypes, and a registry without
    # them is a state no consumer ever runs in.
    def reset!
      @registry = {}
      Policies.register_built_ins!
    end
  end
end
