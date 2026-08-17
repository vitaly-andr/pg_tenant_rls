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
      expect(found).to include(a_string_matching(/unexpected policies widgets_catalog_select/))
    end

    it "accepts the same policies when the manifest declares public_catalog" do
      swapped = %w[catalog_select catalog_insert catalog_update catalog_delete].map do |suffix|
        { name: "widgets_#{suffix}", command: "ALL", permissive: true, roles: ["public"] }
      end
      expect(described_class.problems(table(policies: swapped), :public_catalog)).to be_empty
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

    it "returns true when the perimeter matches" do
      allow(described_class).to receive(:call).and_return([table])
      expect(described_class.verify!(nil, manifest: { widgets: :tenant })).to be(true)
    end

    it "reports a table named in the manifest but absent from the database" do
      allow(described_class).to receive(:call).and_return([])
      expect(described_class.audit(nil, manifest: { widgets: :tenant }))
        .to include(a_string_matching(/table not found/))
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
