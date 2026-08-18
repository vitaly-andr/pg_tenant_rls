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

    # Which archetype declares this policy name for this table, or nil when none does.
    #
    # This is the difference between "a policy from a different archetype is on the table"
    # and "a policy nobody's registry knows about is on the table". The first says the table
    # was switched and something was left behind; the second says a policy is being enforced
    # that no declaration accounts for. Reported as one verdict, they read the same, and the
    # second is the one worth waking up for.
    def owner_of(table, policy_name)
      registry.each_value.find { |archetype| archetype.policy_names(table).include?(policy_name) }
    end

    # The archetype a table's policies correspond to, or nil.
    #
    # Policies no archetype declares — a host override, say — are ignored rather than
    # counted against a match: they are layered on top of an archetype by design. What is
    # compared is the set of policies some archetype does claim, and it has to match one
    # archetype exactly. Leftovers of a half-finished switch therefore identify as nothing,
    # which is the truthful answer: the table is under two archetypes at once.
    def identify(table, policy_names)
      claimed = policy_names.select { |name| owner_of(table, name) }.sort
      return nil if claimed.empty?

      registry.each_value.find { |archetype| archetype.policy_names(table).sort == claimed }&.name
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
