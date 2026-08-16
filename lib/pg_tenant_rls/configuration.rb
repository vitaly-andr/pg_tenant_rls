# frozen_string_literal: true

module PgTenantRls
  # Host-configured contract. The gem is host-/framework-agnostic: it only knows the
  # GUC name, the discriminator column, the key type, and (for GRANTs) the runtime
  # role name. Tenant identity is supplied by the consumer via .configure.
  #
  # There is ONE configuration per process, on purpose. The tenant context belongs to the
  # database session, not to a Ruby object: a per-consumer configuration would not make
  # the database multi-contour, it would only let each consumer believe it had its own
  # while writing to the same session. So the host configures, once; engines mounted in it
  # consume that configuration and must not set their own.
  #
  # Setting an attribute twice to DIFFERENT values raises. That case is not a preference
  # being overridden, it is two components disagreeing about which database contour they
  # are in — and the disagreement is otherwise invisible until the second engine's tables
  # turn out to read a GUC nobody sets.
  class Configuration
    # Attributes that describe the contour. Assigning any of them twice with conflicting
    # values is an error; assigning the same value again is fine (initializers can be
    # re-run, and a matching declaration is not a disagreement).
    CONTRACT = %i[guc discriminator key_type runtime_role policy_role].freeze

    # Session GUC that RLS policies read and Context sets. Reuse a GUC your app already
    # sets per request/job (e.g. "app.current_tenant_id").
    #
    # Note it becomes part of your schema: the name is written literally into every
    # column DEFAULT and every policy predicate, because PostgreSQL offers no indirection
    # for a GUC name inside an expression. See #tenant_function for the way out.
    attr_reader :guc

    # Discriminator column on tenant-scoped tables.
    attr_reader :discriminator

    # SQL type of the tenant key (bigint for integer PKs; change for uuid hosts).
    attr_reader :key_type

    # Unprivileged (NOSUPERUSER/NOBYPASSRLS) runtime role. Target of GRANTs ONLY —
    # required by RoleProvisioner and grant_runtime_privileges!. It deliberately does
    # NOT reach the policy TO clause; see #policy_role.
    attr_reader :runtime_role

    # Role bound into the policy TO clause. nil (the default) means the policies apply
    # to PUBLIC, i.e. to every non-BYPASSRLS role.
    #
    # Keep it nil unless you know you want otherwise. TO <role> adds nothing to
    # isolation (the predicate is unchanged) and costs two things: a policy that does
    # not list the connecting role simply does not apply, so with no other policy the
    # table default-denies and returns zero rows; and the dumped schema stops being
    # portable, since CREATE POLICY ... TO <role> fails to load where the role is absent.
    attr_reader :policy_role

    # Schema-qualified SQL function that returns the current tenant id, e.g.
    # "public.current_tenant_id". When set, DDL calls it instead of inlining
    # current_setting(<guc>) — see Migration#create_tenant_function!. nil keeps the
    # literal form, which is the default and what existing schemas contain.
    #
    # Not part of CONTRACT: unlike the others it is not a claim about which contour we are
    # in, it is a detail of how DDL spells the lookup, and create_tenant_function! sets it
    # as a side effect — so re-running a migration must not raise.
    attr_accessor :tenant_function

    CONTRACT.each do |name|
      define_method("#{name}=") do |value|
        assign(name, value)
      end
    end

    def initialize
      @declared = {}
      @guc = "app.current_tenant_id"
      @discriminator = :tenant_id
      @key_type = :bigint
      @runtime_role = nil
      @policy_role = nil
      @tenant_function = nil
    end

    private

    def assign(name, value)
      previous = @declared[name]
      raise PgTenantRls::Error, conflict_message(name, previous, value) if previous && previous != value

      @declared[name] = value
      instance_variable_set("@#{name}", value)
    end

    def conflict_message(name, previous, value)
      "#{name} is already configured as #{previous.inspect} and cannot be changed to " \
        "#{value.inspect}. There is one tenant contour per process — the tenant context " \
        "lives on the database session, so a second setting would not create a second " \
        "contour, only the belief in one. The host configures this once; engines mounted " \
        "in it consume that configuration rather than declaring their own. Use " \
        "PgTenantRls.reset_config! if you genuinely mean to start over (tests do)."
    end
  end
end
