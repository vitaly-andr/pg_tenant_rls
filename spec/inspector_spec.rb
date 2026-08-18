# frozen_string_literal: true

# The verdict logic is pure — it reads a description of a table, not a database — so it
# is exercised directly here. The catalog queries that BUILD those descriptions need a
# live PostgreSQL and are not covered yet (see OKF-Docs open-decisions §8).
RSpec.describe PgTenantRls::Inspector do
  let(:guc_default) { "NULLIF(current_setting('app.current_team_id'::text, true), ''::text)::bigint" }

  def table(overrides = {})
    { table: "widgets", rls_enabled: true, rls_forced: true, owner: "app",
      discriminator: { column: "tenant_id", type: "bigint", not_null: true, default: guc_default },
      policies: [{ name: "widgets_tenant_all", command: "ALL", permissive: true, roles: ["public"] }],
      foreign_keys_without_discriminator: [] }.merge(overrides)
  end

  before { PgTenantRls.configure { |c| c.guc = "app.current_team_id" } }

  after { PgTenantRls.reset_config! }

  describe "a table that matches its declared archetype" do
    it "reports no problems" do
      expect(described_class.problems(table, :tenant)).to be_empty
    end
  end

  describe "RLS state" do
    it "flags RLS that is off" do
      expect(described_class.problems(table(rls_enabled: false), :tenant))
        .to include(a_string_matching(/RLS is not enabled/))
    end

    it "flags RLS that is on but not forced, because the owner then bypasses policies" do
      expect(described_class.problems(table(rls_forced: false), :tenant))
        .to include(a_string_matching(/not forced/))
    end
  end

  describe "the discriminator column" do
    it "flags a missing column" do
      expect(described_class.problems(table(discriminator: nil), :tenant))
        .to include(a_string_matching(/no discriminator column/))
    end

    # The DEFAULT of a correctly built table stops mentioning the GUC once the indirection
    # function is in use, so checking for the literal name would condemn every such table.
    it "accepts a DEFAULT that calls the indirection function" do
      PgTenantRls.config.tenant_function = "public.current_tenant_id"
      via_function = { column: "tenant_id", type: "bigint", not_null: true,
                       default: "public.current_tenant_id()" }

      expect(described_class.problems(table(discriminator: via_function), :tenant)).to be_empty
    end

    it "still flags a DEFAULT calling some other function" do
      PgTenantRls.config.tenant_function = "public.current_tenant_id"
      wrong = { column: "tenant_id", type: "bigint", not_null: true, default: "public.something_else()" }

      expect(described_class.problems(table(discriminator: wrong), :tenant))
        .to include(a_string_matching(/does not read public\.current_tenant_id/))
    end

    it "flags a DEFAULT wired to a different GUC — the 022 failure mode" do
      stale = { column: "tenant_id", type: "bigint", not_null: true,
                default: "NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text)::bigint" }
      expect(described_class.problems(table(discriminator: stale), :tenant))
        .to include(a_string_matching(/does not read app\.current_team_id/))
    end
  end

  describe "archetype substitution — the check 'a policy exists' cannot make" do
    it "catches public_catalog policies where the manifest declares tenant" do
      swapped = %w[catalog_select catalog_insert catalog_update catalog_delete].map do |suffix|
        { name: "widgets_#{suffix}", command: "ALL", permissive: true, roles: ["public"] }
      end
      found = described_class.problems(table(policies: swapped), :tenant)
      expect(found).to include(a_string_matching(/missing policies widgets_tenant_all/))
      expect(found).to include(a_string_matching(/another archetype: widgets_catalog_select \(public_catalog\)/))
    end

    it "accepts the same policies when the manifest declares public_catalog" do
      swapped = %w[catalog_select catalog_insert catalog_update catalog_delete].map do |suffix|
        { name: "widgets_#{suffix}", command: "ALL", permissive: true, roles: ["public"] }
      end
      expect(described_class.problems(table(policies: swapped), :public_catalog)).to be_empty
    end
  end

  # FR-009. Both used to be reported as "unexpected policies", and the two are not the same
  # finding: one says a switch did not finish, the other says something is being enforced
  # that no declaration accounts for.
  describe "a policy that is not part of the declared archetype" do
    def with_policies(*names)
      described_class.problems(
        table(policies: names.map { |n| { name: n, command: "ALL", permissive: true, roles: ["public"] } }),
        :tenant
      )
    end

    it "is attributed to the archetype that declares it, when one does" do
      expect(with_policies("widgets_tenant_all", "widgets_shared_select"))
        .to include(a_string_matching(/another archetype: widgets_shared_select \(shared_default\)/))
    end

    it "is reported as belonging to no archetype otherwise" do
      expect(with_policies("widgets_tenant_all", "widgets_super_admin_all"))
        .to include(a_string_matching(/no registered archetype: widgets_super_admin_all/))
    end

    it "keeps the two apart when a table carries both" do
      found = with_policies("widgets_tenant_all", "widgets_shared_select", "widgets_super_admin_all")
      expect(found).to include(a_string_matching(/another archetype: widgets_shared_select/))
      expect(found).to include(a_string_matching(/no registered archetype: widgets_super_admin_all/))
    end

    it "attributes a host-registered archetype's policy just as readily" do
      PgTenantRls.register_archetype(:membership) do |a|
        a.discriminator false
        a.policy :membership_select, command: "SELECT", using: "id IN (SELECT portal_team_ids())"
      end

      expect(with_policies("widgets_tenant_all", "widgets_membership_select"))
        .to include(a_string_matching(/another archetype: widgets_membership_select \(membership\)/))
    ensure
      PgTenantRls::Archetypes.reset!
    end
  end

  # FR-011. The question asked when there is no manifest yet: an existing schema has to be
  # inventoried before it can be declared.
  describe ".identify" do
    def identify(*names)
      policies = names.map { |n| { name: n, command: "ALL", permissive: true, roles: ["public"] } }
      allow(described_class).to receive(:call).and_return([table(policies: policies)])
      described_class.identify(nil, :widgets)
    end

    it "names the archetype a table's policies correspond to" do
      expect(identify("widgets_tenant_all")).to eq(:tenant)
      expect(identify(*%w[widgets_catalog_select widgets_catalog_insert
                          widgets_catalog_update widgets_catalog_delete])).to eq(:public_catalog)
    end

    # An override is layered on top of an archetype by design, so counting it against the
    # match would make every table the portal touches unidentifiable.
    it "ignores a policy no archetype declares" do
      expect(identify("widgets_tenant_all", "widgets_super_admin_all")).to eq(:tenant)
    end

    it "names none when the table carries the leftovers of two archetypes" do
      expect(identify("widgets_tenant_all", "widgets_shared_select")).to be_nil
    end

    it "names none for a table under no archetype at all" do
      expect(identify("widgets_super_admin_all")).to be_nil
    end

    it "names none rather than raising for a table that does not exist" do
      allow(described_class).to receive(:call).and_return([])
      expect(described_class.identify(nil, :missing)).to be_nil
    end
  end

  describe "restrictive policies" do
    it "surfaces them even when the expected set matches, since they narrow with AND" do
      policies = [{ name: "widgets_tenant_all", command: "ALL", permissive: true, roles: ["public"] },
                  { name: "widgets_extra", command: "ALL", permissive: false, roles: ["public"] }]
      expect(described_class.problems(table(policies: policies), :tenant))
        .to include(a_string_matching(/widgets_extra is RESTRICTIVE/))
    end
  end

  describe ".verify!" do
    it "raises listing every problem" do
      allow(described_class).to receive(:call).and_return([table(rls_forced: false)])
      expect { described_class.verify!(nil, manifest: { widgets: :tenant }) }
        .to raise_error(PgTenantRls::Error, /not forced/)
    end

    it "returns the report when the perimeter matches, saying what it looked at" do
      allow(described_class).to receive(:call).and_return([table])
      report = described_class.verify!(nil, manifest: { widgets: :tenant })

      expect(report.clean?).to be(true)
      expect(report.checked).to include("table widgets (tenant)")
    end

    it "reports a table named in the manifest but absent from the database" do
      allow(described_class).to receive(:call).and_return([])
      expect(described_class.audit(nil, manifest: { widgets: :tenant }).problems)
        .to include(a_string_matching(/table not found/))
    end

    # The defect this Report exists for: a bare list of problems answers "was anything wrong"
    # and cannot answer "was anything examined", so an audit that had quietly stopped looking
    # returned exactly what a clean perimeter returns.
    it "refuses an audit that examined nothing, as loudly as one that found something" do
      allow(described_class).to receive(:call).and_return([])

      expect { described_class.verify!(nil, manifest: {}) }
        .to raise_error(PgTenantRls::Error, /examined nothing/)
    end

    it "says which questions it did not ask, and why" do
      allow(described_class).to receive(:call).and_return([table])
      report = described_class.audit(nil, manifest: { widgets: :tenant })

      expect(report.skipped).to include(a_string_matching(/perimeter: no prefixes given/))
      expect(report.skipped).to include(a_string_matching(/config\.runtime_role is not set/))
    end

    it "counts the perimeter sweep as coverage even when the manifest is empty" do
      allow(described_class).to receive(:call).and_return([])
      report = described_class.audit(nil, manifest: {}, prefixes: ["shop_"])

      expect(report.nothing_checked?).to be(false)
      expect(report.checked).to include("perimeter shop_")
    end
  end

  describe ".enforced_for_current_role?" do
    it "is false under BYPASSRLS — policies are inert and a green test means nothing" do
      connection = double(select_one: { "rolsuper" => false, "rolbypassrls" => true })
      expect(described_class.enforced_for_current_role?(connection)).to be(false)
    end

    it "is false for a superuser, for the same reason" do
      connection = double(select_one: { "rolsuper" => true, "rolbypassrls" => false })
      expect(described_class.enforced_for_current_role?(connection)).to be(false)
    end

    it "is true for an unprivileged role" do
      connection = double(select_one: { "rolsuper" => false, "rolbypassrls" => false })
      expect(described_class.enforced_for_current_role?(connection)).to be(true)
    end
  end
end
