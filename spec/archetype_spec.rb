# frozen_string_literal: true

# The registry and the two entities behind it. No database: these are declarations, and what
# they describe is checked against a live catalogue elsewhere.
RSpec.describe PgTenantRls::Archetype do
  describe "declaring a policy" do
    it "builds the policy name from the table and the suffix" do
      archetype = described_class.new(:demo).policy(:demo_all, command: "ALL", using: "true")

      expect(archetype.policy_names("widgets")).to eq(["widgets_demo_all"])
    end

    it "takes an explicit name instead, so a schema's existing policies can be adopted" do
      archetype = described_class.new(:demo)
                                 .policy(name: "portal_stores_owner_insert", command: "INSERT", check: "true")

      expect(archetype.policy_names("portal_stores")).to eq(["portal_stores_owner_insert"])
    end

    it "needs one of the two" do
      expect { described_class.new(:demo).policy(command: "ALL", using: "true") }
        .to raise_error(PgTenantRls::Error, /suffix or an explicit name/)
    end
  end

  # PostgreSQL fixes which clause each command accepts. A declaration breaking that rule can
  # only produce a statement the database rejects, so it is refused where it is written.
  describe "clause rules" do
    subject(:archetype) { described_class.new(:demo) }

    it "refuses WITH CHECK on SELECT" do
      expect { archetype.policy(:s, command: "SELECT", using: "true", check: "true") }
        .to raise_error(PgTenantRls::Error, /SELECT takes no WITH CHECK/)
    end

    it "refuses WITH CHECK on DELETE" do
      expect { archetype.policy(:d, command: "DELETE", using: "true", check: "true") }
        .to raise_error(PgTenantRls::Error, /DELETE takes no WITH CHECK/)
    end

    it "refuses USING on INSERT" do
      expect { archetype.policy(:i, command: "INSERT", using: "true") }
        .to raise_error(PgTenantRls::Error, /INSERT takes no USING/)
    end

    it "accepts both on UPDATE, which genuinely takes both" do
      expect { archetype.policy(:u, command: "UPDATE", using: "true", check: "true") }.not_to raise_error
    end

    it "refuses a policy with no expression at all" do
      expect { archetype.policy(:empty, command: "ALL") }
        .to raise_error(PgTenantRls::Error, /needs a USING or WITH CHECK/)
    end

    it "refuses a command PostgreSQL does not have" do
      expect { archetype.policy(:t, command: "TRUNCATE", using: "true") }
        .to raise_error(PgTenantRls::Error, /unknown command/)
    end
  end

  describe "validation of the archetype as a whole" do
    it "refuses one that declares nothing" do
      expect { described_class.new(:empty).validate! }
        .to raise_error(PgTenantRls::Error, /declares no policies/)
    end

    # Documented: "If only restrictive policies exist, then no records will be accessible."
    # Catching it here beats catching it as an empty result on the first query.
    it "refuses one that is only restrictive, since that table is readable by nobody" do
      archetype = described_class.new(:narrowing)
                                 .policy(:only, command: "ALL", permissive: false, using: "true")

      expect { archetype.validate! }
        .to raise_error(PgTenantRls::Error, /readable by nobody/)
    end

    it "accepts a restrictive policy alongside a permissive one" do
      archetype = described_class.new(:mixed)
                                 .policy(:wide, command: "ALL", using: "true")
                                 .policy(:narrow, command: "ALL", permissive: false, using: "false")

      expect { archetype.validate! }.not_to raise_error
    end
  end

  describe "what the archetype needs of the table" do
    it "wants a non-null discriminator by default" do
      archetype = described_class.new(:demo).policy(:a, command: "ALL", using: "true")

      expect(archetype.discriminator?).to be(true)
      expect(archetype.nullable_discriminator?).to be(false)
    end

    it "can want none at all — a shared catalogue belongs to nobody" do
      archetype = described_class.new(:reference).discriminator(false)

      expect(archetype.discriminator?).to be(false)
    end

    it "can want one that admits null" do
      archetype = described_class.new(:shared).discriminator(true, nullable: true)

      expect(archetype.nullable_discriminator?).to be(true)
    end
  end
end

RSpec.describe PgTenantRls::Archetypes do
  after { described_class.reset! }

  def archetype(name, using: "true")
    PgTenantRls::Archetype.new(name).policy(:"#{name}_all", command: "ALL", using: using)
  end

  describe "registering" do
    it "makes an archetype fetchable by name" do
      described_class.register(archetype(:demo))

      expect(described_class.fetch(:demo).name).to eq(:demo)
    end

    it "accepts the same definition twice — initializers get re-run" do
      described_class.register(archetype(:demo))

      expect { described_class.register(archetype(:demo)) }.not_to raise_error
    end

    # Two components disagreeing about what a name means is the failure worth catching: it
    # otherwise surfaces later as a policy nobody expected on a table nobody suspected.
    it "refuses a different definition under a name already taken" do
      described_class.register(archetype(:demo, using: "true"))

      expect { described_class.register(archetype(:demo, using: "false")) }
        .to raise_error(PgTenantRls::Error, /already registered with a different definition/)
    end

    it "refuses to register something invalid" do
      empty = PgTenantRls::Archetype.new(:empty)

      expect { described_class.register(empty) }.to raise_error(PgTenantRls::Error, /declares no policies/)
    end
  end

  describe "fetching" do
    it "names the archetype and what is registered when it is unknown" do
      described_class.register(archetype(:known))

      expect { described_class.fetch(:missing) }
        .to raise_error(PgTenantRls::Error, /unknown archetype :missing.*registered:.*known/m)
    end
  end

  describe "what the gem itself registers" do
    # FR-012: the built-ins travel the registry too, so the mechanism cannot drift from the
    # archetypes it was built for. A registry that starts empty would leave that door
    # unexercised by anything the gem relies on.
    it "holds every archetype the gem ships, before a host registers anything" do
      expect(described_class.names)
        .to include(:tenant, :shared_default, :public_read, :gated_read, :reference, :public_catalog)
    end

    it "states what each one needs of the table, which is what spares the caller a list" do
      expect(described_class.fetch(:tenant).discriminator?).to be(true)
      expect(described_class.fetch(:tenant).nullable_discriminator?).to be(false)
      expect(described_class.fetch(:shared_default).nullable_discriminator?).to be(true)
      expect(described_class.fetch(:reference).discriminator?).to be(false)
    end
  end

  describe "the boundary of what pruning may remove" do
    it "spans every registered archetype" do
      described_class.register(archetype(:one))
      described_class.register(archetype(:two))

      expect(described_class.all_policy_names("widgets"))
        .to include("widgets_one_all", "widgets_two_all", "widgets_tenant_all")
    end

    it "excludes names no archetype declares, which is what keeps a host's own policy safe" do
      described_class.register(archetype(:one))

      expect(described_class.all_policy_names("widgets")).not_to include("widgets_super_admin_all")
    end
  end
end

RSpec.describe "PgTenantRls.register_archetype" do
  after { PgTenantRls::Archetypes.reset! }

  it "declares an archetype through the block form a host uses" do
    PgTenantRls.register_archetype(:membership) do |a|
      a.discriminator false
      a.policy :membership_select, command: "SELECT", using: "id IN (SELECT team_ids())"
    end

    registered = PgTenantRls::Archetypes.fetch(:membership)
    expect(registered.discriminator?).to be(false)
    expect(registered.policy_names("teams")).to eq(["teams_membership_select"])
  end

  it "writes the host's expression verbatim, having no opinion about it" do
    PgTenantRls.register_archetype(:opaque) do |a|
      a.policy :opaque_all, command: "ALL", using: "whatever_the_host_means()"
    end

    declaration = PgTenantRls::Archetypes.fetch(:opaque).policies.first
    expect(declaration.using).to eq("whatever_the_host_means()")
  end
end
