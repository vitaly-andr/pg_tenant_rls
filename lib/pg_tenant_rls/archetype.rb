# frozen_string_literal: true

module PgTenantRls
  # A named access pattern: the policies it consists of, and what it needs of the table.
  #
  # Built by the block form of PgTenantRls.register_archetype:
  #
  #   PgTenantRls.register_archetype(:membership) do |a|
  #     a.discriminator false
  #     a.policy :membership_select, command: "SELECT", using: "id IN (SELECT team_ids())"
  #   end
  #
  # The discriminator facts live here rather than with the caller because the archetype's own
  # predicates already reference that column — an archetype cannot be indifferent to whether
  # it exists. Keeping them apart is what produced four separate lists in a consumer, one of
  # which then diverged.
  class Archetype
    # Where the discriminator's name comes from when a registration does not override it.
    # Asked for at apply time, not at declaration time: the gem registers its own archetypes
    # as it loads, which is before any host initializer has said what the column is called.
    DISCRIMINATOR_NAME = -> { PgTenantRls.config.discriminator }

    attr_reader :name, :policies

    def initialize(name)
      @name = name.to_sym
      @policies = []
      @options = {}
      @discriminator = true
      @nullable_discriminator = false
      option(:column, DISCRIMINATOR_NAME)
    end

    # Declare a policy. `suffix` builds the name as "<table>_<suffix>"; pass `name:` instead to
    # adopt a policy name a schema already uses. The rest — command, permissive, using,
    # check — is the declaration itself and is handed straight to it, so the two cannot
    # disagree about what a policy may be given.
    def policy(suffix = nil, **declaration)
      @policies << PolicyDeclaration.new(suffix: suffix, **declaration)
      self
    end

    # Whether tables under this archetype carry the discriminator column, and whether it
    # admits null. A shared catalogue owned by nobody sets `discriminator false`.
    def discriminator(required = nil, nullable: nil)
      @discriminator = required unless required.nil?
      @nullable_discriminator = nullable unless nullable.nil?
      self
    end

    def discriminator? = @discriminator
    def nullable_discriminator? = @nullable_discriminator

    # Declare an argument the archetype's expressions are built from — the discriminator
    # column, a published flag, a gate table, a predicate naming an administrator.
    #
    # A default that responds to #call is asked for its value when the archetype is applied,
    # not when it is declared: the configuration a host writes in an initializer is not
    # necessarily in place at the moment the gem registers its own archetypes.
    def option(name, default = nil, required: false)
      @options[name.to_sym] = { default: default, required: required }
      self
    end

    # Values for every declared option, with defaults filled in.
    #
    # An option that was never declared raises rather than being ignored. Silently dropping
    # `published_colum:` would write a policy against the wrong column and report success,
    # which is the failure this project keeps paying for: the mistake is in what was made
    # possible, not in what the statement did.
    def resolve_options(given)
      unknown = given.keys.map(&:to_sym) - @options.keys
      unless unknown.empty?
        raise PgTenantRls::Error,
              "archetype #{name} takes no option #{unknown.map(&:inspect).join(", ")}; " \
              "it takes #{@options.keys.map(&:inspect).join(", ")}"
      end

      @options.each_key.to_h { |key| [key, resolve_option(key, given)] }
    end

    def policy_names(table)
      policies.map { |declaration| declaration.policy_name(table) }
    end

    def ==(other)
      other.is_a?(self.class) && to_h == other.to_h
    end
    alias eql? ==

    def hash = to_h.hash

    def to_h
      { name: name, policies: policies.map(&:to_h), options: @options,
        discriminator: @discriminator, nullable_discriminator: @nullable_discriminator }
    end

    # Raised at registration rather than at first query: a table whose policies are all
    # restrictive is readable by nobody. PostgreSQL states it plainly — "there needs to be at
    # least one permissive policy to grant access to records before restrictive policies can
    # be usefully used… If only restrictive policies exist, then no records will be accessible."
    def validate!
      raise PgTenantRls::Error, "archetype #{name} declares no policies" if policies.empty?
      return if policies.any?(&:permissive?)

      raise PgTenantRls::Error,
            "archetype #{name} declares only restrictive policies, which leaves the table " \
            "readable by nobody — at least one permissive policy must grant access first"
    end

    private

    def resolve_option(key, given)
      return given[key] if given.key?(key)

      spec = @options.fetch(key)
      raise PgTenantRls::Error, "archetype #{name} needs option #{key.inspect}" if spec[:required]

      spec[:default].respond_to?(:call) ? spec[:default].call : spec[:default]
    end
  end
end
