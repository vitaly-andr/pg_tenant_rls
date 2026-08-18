# frozen_string_literal: true

# Unit-level check of the migration DSL: a harness captures the SQL that each
# archetype would execute, stubbing ActiveRecord quoting. No database required.
RSpec.describe PgTenantRls::Migration do
  let(:harness) do
    Class.new do
      include PgTenantRls::Migration

      attr_reader :executed, :queries
      # Catalog answers. Both nil by default: no policy exists (so recreate_policy!
      # takes the CREATE branch) and the column owns no sequence.
      # Named flags_value, not rls_flags: the DSL already has a private rls_flags(table),
      # and an accessor of that name would shadow it.
      #
      # existing_shape is polcmd and polpermissive joined, the way the catalog read returns
      # them: "*1" is a permissive ALL policy, "*0" the same command made restrictive.
      attr_accessor :existing_shape, :sequence_name, :flags_value

      def initialize
        super
        @executed = []
        @queries = []
      end

      def execute(sql)
        @executed << sql
      end

      def quote_table_name(name)
        %("#{name}")
      end

      def quote_column_name(name)
        %("#{name}")
      end

      def quote(value)
        "'#{value}'"
      end

      # This harness deliberately implements exactly the methods a real consumer proxies
      # — execute, the three quoting helpers and select_values — and nothing more. A
      # hand-rolled adapter forwarding a short list of connection methods is a normal way
      # to use this DSL (Kub::Tenancy::MigrationAdapter does precisely that). If the DSL
      # starts calling anything outside this list, these specs must fail, because that
      # consumer would fail too, with a NoMethodError at runtime.
      def select_values(sql)
        @queries << sql
        return [@existing_shape].compact if sql.include?("polcmd")
        return [@sequence_name].compact if sql.include?("pg_get_serial_sequence")
        return [@flags_value].compact if sql.include?("relrowsecurity")

        []
      end
    end.new
  end

  let(:sql) { harness.executed.join("\n") }
  let(:guc_cast) { "NULLIF(current_setting('app.current_team_id', true), '')::bigint" }

  before do
    PgTenantRls.configure do |c|
      c.guc           = "app.current_team_id"
      c.discriminator = :tenant_id
      c.key_type      = :bigint
      c.runtime_role  = "app_runtime"
    end
  end

  after { PgTenantRls.reset_config! }

  describe "#create_tenant_policy! (isolated)" do
    before { harness.create_tenant_policy!(:widgets) }

    it "creates an ALL policy with NO TO clause, even though runtime_role is set" do
      expect(sql).to include(%(CREATE POLICY widgets_tenant_all ON "widgets" FOR ALL USING))
      expect(sql).not_to include("TO app_runtime")
    end

    it "isolates by discriminator = current tenant for both USING and WITH CHECK" do
      expect(sql).to include(%(USING ("tenant_id" = #{guc_cast})))
      expect(sql).to include(%(WITH CHECK ("tenant_id" = #{guc_cast})))
    end
  end

  describe "#create_shared_default_policy!" do
    before { harness.create_shared_default_policy!(:price_types) }

    it "reads own rows OR global defaults (discriminator IS NULL)" do
      expect(sql).to include(%(price_types_shared_select))
      expect(sql).to include(%(("tenant_id" = #{guc_cast} OR "tenant_id" IS NULL)))
    end

    it "writes own rows only (INSERT/DELETE keyed to current tenant)" do
      expect(sql).to include(%(price_types_shared_insert ON "price_types" FOR INSERT))
      expect(sql).to include(%(price_types_shared_delete ON "price_types" FOR DELETE))
    end

    it "restricts UPDATE to own rows, not the global defaults" do
      update_line = harness.executed.find { |s| s.include?("CREATE POLICY price_types_shared_update") }
      expect(update_line).to include(%(USING ("tenant_id" = #{guc_cast})))
      expect(update_line).not_to include("IS NULL")
    end
  end

  describe "#create_public_read_policy!" do
    before { harness.create_public_read_policy!(:products, published_column: :published) }

    it "reads published rows OR own rows" do
      expect(sql).to include(%(products_public_select))
      expect(sql).to include(%(("published" OR "tenant_id" = #{guc_cast})))
    end

    it "writes own rows only" do
      expect(sql).to include(%(products_public_insert ON "products" FOR INSERT))
      expect(sql).to include(%(WITH CHECK ("tenant_id" = #{guc_cast})))
    end
  end

  describe "#create_public_catalog_policy!" do
    before { harness.create_public_catalog_policy!(:products) }

    it "reads every row when there is no tenant context, else only own" do
      expect(sql).to include(%(products_catalog_select))
      expect(sql).to include(%((#{guc_cast} IS NULL OR "tenant_id" = #{guc_cast})))
    end

    it "writes own rows only (INSERT/UPDATE/DELETE keyed to current tenant)" do
      expect(sql).to include(%(products_catalog_insert ON "products" FOR INSERT))
      expect(sql).to include(%(products_catalog_update ON "products" FOR UPDATE))
      expect(sql).to include(%(products_catalog_delete ON "products" FOR DELETE))
      expect(sql).to include(%(WITH CHECK ("tenant_id" = #{guc_cast})))
    end
  end

  describe "#create_gated_read_policy!" do
    before do
      harness.create_gated_read_policy!(:kub_products, gate: { table: "kub_publications", fk: "kub_product_id" })
    end

    it "reads rows the gate table marks published OR own rows" do
      expect(sql).to include("kub_products_gated_select")
      expect(sql).to include('EXISTS (SELECT 1 FROM "kub_publications" g WHERE')
      expect(sql).to include('g."kub_product_id" = "kub_products".id')
      expect(sql).to include('AND g."published"')
      expect(sql).to include(%(OR "tenant_id" = #{guc_cast}))
    end

    it "writes own rows only (INSERT/UPDATE/DELETE keyed to current tenant)" do
      expect(sql).to include(%(kub_products_gated_insert ON "kub_products" FOR INSERT))
      expect(sql).to include(%(kub_products_gated_update ON "kub_products" FOR UPDATE))
      expect(sql).to include(%(kub_products_gated_delete ON "kub_products" FOR DELETE))
      expect(sql).to include(%(WITH CHECK ("tenant_id" = #{guc_cast})))
    end

    it "honors a custom published_column" do
      harness.create_gated_read_policy!(:widgets, gate: { table: "gate_widgets", fk: "widget_id" },
                                                  published_column: :is_live)
      expect(sql).to include(%(g."is_live"))
    end
  end

  describe "#create_reference_policy! — shared to read, admin-only to write" do
    let(:admin) { "COALESCE(NULLIF(current_setting('app.is_super_admin', true), '')::boolean, false)" }

    before { harness.create_reference_policy!(:kub_categories, writable_when: admin) }

    it "lets everyone read, with no tenant condition at all" do
      expect(sql).to include(%(CREATE POLICY kub_categories_reference_select ON "kub_categories" FOR SELECT))
      expect(sql).to include("USING (true)")
    end

    it "admits writes only under the host's predicate" do
      %w[insert update delete].each do |command|
        line = harness.executed.find { |s| s.include?("kub_categories_reference_#{command}") }
        expect(line).to include(admin)
      end
    end

    it "never mentions the discriminator — these rows belong to nobody" do
      expect(sql).not_to include("tenant_id")
    end
  end

  describe "#add_tenant_column!" do
    before { harness.add_tenant_column!(:widgets) }

    it "is idempotent (ADD COLUMN IF NOT EXISTS) with a DB DEFAULT from the GUC" do
      expect(sql).to include(%(ADD COLUMN IF NOT EXISTS "tenant_id" bigint DEFAULT #{guc_cast} NOT NULL))
    end
  end

  # The hijack warning exists to be read. It fires when another module has taken over one of
  # these names in ActiveRecord::Migration — and it fired on every boot of every consumer,
  # naming this gem's own modules, from the moment the DSL was split across several of them.
  # A warning that always fires teaches people to ignore it, and then the real one passes
  # unread. This is the check that catches the next split.
  describe ".own? — which module counts as this gem" do
    it "recognises every public helper as its own" do
      strangers = described_class.public_instance_methods.reject do |name|
        described_class.own?(described_class.instance_method(name).owner)
      end

      expect(strangers).to be_empty
    end

    it "recognises the modules the DSL is assembled from" do
      expect(described_class.own?(PgTenantRls::Policies)).to be(true)
      expect(described_class.own?(PgTenantRls::ForeignKeys)).to be(true)
      expect(described_class.own?(PgTenantRls::PolicyStatements)).to be(true)
    end

    it "does not recognise a module from elsewhere — otherwise the warning could never fire" do
      expect(described_class.own?(Module.new)).to be(false)
    end
  end

  describe "policy_role — the TO clause, separate from runtime_role" do
    it "writes TO only when policy_role is set" do
      PgTenantRls.config.policy_role = "app_runtime"
      harness.create_tenant_policy!(:widgets)
      expect(sql).to include(%(FOR ALL TO app_runtime))
    end

    it "still takes an explicit role: argument" do
      harness.create_tenant_policy!(:widgets, role: "reporting")
      expect(sql).to include(%(FOR ALL TO reporting))
    end
  end

  describe "policy rewrite — ALTER over DROP + CREATE" do
    it "alters in place when a policy of the same command already exists" do
      harness.existing_shape = "*1"
      harness.create_tenant_policy!(:widgets)
      expect(sql).to include(%(ALTER POLICY widgets_tenant_all ON "widgets" TO PUBLIC))
      expect(sql).not_to include("DROP POLICY")
      expect(sql).not_to include("CREATE POLICY")
    end

    it "spells out TO PUBLIC so a stale role binding is cleared, not left behind" do
      harness.existing_shape = "*1"
      harness.create_tenant_policy!(:widgets)
      expect(sql).to include("TO PUBLIC")
    end

    it "falls back to DROP + CREATE when the command differs" do
      harness.existing_shape = "r1" # SELECT, but the archetype wants ALL
      harness.create_tenant_policy!(:widgets)
      expect(sql).to include("DROP POLICY widgets_tenant_all")
      expect(sql).to include("CREATE POLICY widgets_tenant_all")
    end

    # IF EXISTS would be asking the database to tell us something the catalog read a
    # moment earlier already answered.
    it "issues no DROP at all when there is no policy to replace" do
      harness.create_tenant_policy!(:widgets)
      expect(sql).not_to include("DROP POLICY")
      expect(sql).to include("CREATE POLICY widgets_tenant_all")
    end
  end

  describe "#enable_tenant_rls! — no ALTER when the flag is already set" do
    it "issues both statements on a table that has neither" do
      harness.flags_value = "00"
      harness.enable_tenant_rls!(:widgets)
      expect(sql).to include("ENABLE ROW LEVEL SECURITY")
      expect(sql).to include("FORCE ROW LEVEL SECURITY")
    end

    it "issues nothing when row security is already enabled and forced" do
      harness.flags_value = "11"
      harness.enable_tenant_rls!(:widgets)
      expect(sql).not_to include("ALTER TABLE")
    end

    # The flags are independent, and this is the case worth guarding: skipping FORCE
    # because ENABLE is set would leave the owner bypassing every policy.
    it "still forces a table that is enabled but not forced" do
      harness.flags_value = "10"
      harness.enable_tenant_rls!(:widgets)
      expect(sql).to include("FORCE ROW LEVEL SECURITY")
      expect(sql).not_to include("ENABLE ROW LEVEL SECURITY")
    end

    it "skips FORCE entirely when the caller asked not to force" do
      harness.flags_value = "00"
      harness.enable_tenant_rls!(:widgets, force: false)
      expect(sql).to include("ENABLE ROW LEVEL SECURITY")
      expect(sql).not_to include("FORCE ROW LEVEL SECURITY")
    end

    it "falls through to both ALTERs for an unknown table, rather than doing nothing" do
      harness.flags_value = nil
      harness.enable_tenant_rls!(:widgets)
      expect(sql).to include("ENABLE ROW LEVEL SECURITY")
      expect(sql).to include("FORCE ROW LEVEL SECURITY")
    end
  end

  describe "#apply_tenant_archetype! — reaching an archetype without stripping the table" do
    it "writes the archetype's policies" do
      harness.apply_tenant_archetype!(:widgets, :tenant)
      expect(sql).to include("CREATE POLICY widgets_tenant_all")
    end

    it "issues no DROP when the table carries nothing else" do
      harness.apply_tenant_archetype!(:widgets, :tenant)
      expect(sql).not_to include("DROP POLICY")
    end

    it "removes leftovers of a previous archetype" do
      allow(harness).to receive(:policy_names).and_return(
        %w[widgets_catalog_select widgets_catalog_insert widgets_tenant_all]
      )
      harness.apply_tenant_archetype!(:widgets, :tenant)
      expect(sql).to include(%(DROP POLICY IF EXISTS "widgets_catalog_select"))
      expect(sql).to include(%(DROP POLICY IF EXISTS "widgets_catalog_insert"))
    end

    it "keeps the policies of the archetype being applied" do
      allow(harness).to receive(:policy_names).and_return(%w[widgets_tenant_all])
      harness.apply_tenant_archetype!(:widgets, :tenant)
      expect(sql).not_to include("DROP POLICY")
    end

    # The reason to prefer this over drop_tenant_policies!: a host override survives.
    it "leaves policies this gem never wrote alone" do
      allow(harness).to receive(:policy_names).and_return(
        %w[widgets_tenant_all widgets_super_admin_all portal_custom_policy]
      )
      harness.apply_tenant_archetype!(:widgets, :tenant)
      expect(sql).not_to include("DROP POLICY")
    end

    it "accepts the archetype's own options" do
      harness.apply_tenant_archetype!(:products, :public_read, published_column: :is_live)
      expect(sql).to include(%(("is_live" OR "tenant_id" = #{guc_cast})))
    end
  end

  # US1: an archetype the gem knows nothing about, declared the way a host declares one.
  # Nothing in lib/ names :membership, portal_team_ids() or owner_id — that is the seam.
  describe "an archetype the host registered" do
    before do
      PgTenantRls.register_archetype(:membership) do |a|
        a.discriminator false
        a.policy :membership_select, command: "SELECT", using: "id IN (SELECT portal_team_ids())"
        a.policy name: "teams_owner_insert", command: "INSERT", check: "owner_id = portal_user_id()"
      end
    end

    after { PgTenantRls::Archetypes.reset! }

    it "writes the policies the declaration names, with its expressions untouched" do
      harness.apply_tenant_archetype!(:teams, :membership)
      expect(sql).to include(
        %(CREATE POLICY teams_membership_select ON "teams" FOR SELECT USING (id IN (SELECT portal_team_ids()));)
      )
    end

    # FR-005. A rename of live policy objects buys nothing functional, so an archetype is
    # allowed to adopt the names a schema already carries.
    it "adopts an explicit policy name rather than imposing the suffix rule" do
      harness.apply_tenant_archetype!(:teams, :membership)
      expect(sql).to include(%(CREATE POLICY teams_owner_insert ON "teams" FOR INSERT))
      expect(sql).not_to include("teams_membership_insert")
    end

    it "asks for no discriminator column, because the declaration says the rows have no owner" do
      harness.apply_tenant_archetype!(:teams, :membership)
      expect(sql).not_to include("ADD COLUMN")
    end

    # FR-010 in the direction that used to be impossible: pruning knew only the gem's own
    # names, so a host archetype's policies survived every switch away from it.
    it "has its policies pruned when the table moves to a built-in archetype" do
      allow(harness).to receive(:policy_names).and_return(%w[widgets_membership_select widgets_tenant_all])
      harness.apply_tenant_archetype!(:widgets, :tenant)
      expect(sql).to include(%(DROP POLICY IF EXISTS "widgets_membership_select"))
    end

    it "prunes a built-in archetype's policies when a table moves to it" do
      allow(harness).to receive(:policy_names).and_return(%w[teams_tenant_all teams_membership_select])
      harness.apply_tenant_archetype!(:teams, :membership)
      expect(sql).to include(%(DROP POLICY IF EXISTS "teams_tenant_all"))
    end

    it "still leaves alone a policy no archetype declares" do
      allow(harness).to receive(:policy_names).and_return(%w[teams_membership_select teams_super_admin_all])
      harness.apply_tenant_archetype!(:teams, :membership)
      expect(sql).not_to include("teams_super_admin_all")
    end

    # FR-008. Dispatching by method name answered this with NoMethodError, which names the
    # method the gem happens to use rather than the archetype the caller asked for.
    it "raises for a name nobody registered, listing what is registered" do
      expect { harness.apply_tenant_archetype!(:teams, :nonesuch) }
        .to raise_error(PgTenantRls::Error, /unknown archetype :nonesuch.*registered:.*membership/m)
    end

    it "raises for an option the archetype never declared, rather than dropping it" do
      expect { harness.apply_tenant_archetype!(:teams, :membership, published_column: :live) }
        .to raise_error(PgTenantRls::Error, /takes no option :published_column/)
    end
  end

  # The facts that used to live with the caller, as four lists it had to keep in step.
  describe "the discriminator column an archetype declares it needs" do
    it "is added when the archetype wants one and the table has none" do
      harness.apply_tenant_archetype!(:widgets, :tenant)
      expect(sql).to include(%(ADD COLUMN IF NOT EXISTS "tenant_id" bigint))
      expect(sql).to include("NOT NULL")
    end

    it "admits null where the archetype's own predicate reads rows belonging to nobody" do
      harness.apply_tenant_archetype!(:widgets, :shared_default)
      expect(sql).to include(%(ADD COLUMN IF NOT EXISTS "tenant_id" bigint))
      expect(sql).not_to include("NOT NULL")
    end

    # ADD COLUMN IF NOT EXISTS would be correct and still wrong: ALTER TABLE takes an
    # ACCESS EXCLUSIVE lock whether or not it has anything to do, and this runs for every
    # table on every reconcile.
    it "is not touched when the table already carries it" do
      allow(harness).to receive(:column_present?).and_return(true)
      harness.apply_tenant_archetype!(:widgets, :tenant)
      expect(sql).not_to include("ADD COLUMN")
    end

    it "is never asked for by an archetype whose rows belong to nobody" do
      harness.apply_tenant_archetype!(:manuals, :reference, writable_when: "app_is_admin()")
      expect(sql).not_to include("ADD COLUMN")
    end
  end

  describe "#drop_tenant_policies!" do
    before { harness.drop_tenant_policies!(:widgets) }

    it "identifies the table through to_regclass, not by bare name" do
      expect(harness.queries.join).to include("FROM pg_policy WHERE polrelid = to_regclass('widgets')")
    end

    it "does not fall back to pg_policies, which omits the schema" do
      expect(harness.queries.join).not_to include("pg_policies")
    end
  end

  describe "#grant_runtime_privileges!" do
    it "asks the catalog which sequence the column owns" do
      harness.sequence_name = "public.widgets_id_seq"
      harness.grant_runtime_privileges!(:widgets)
      expect(sql).to include("GRANT USAGE, SELECT ON SEQUENCE public.widgets_id_seq TO app_runtime;")
    end

    it "skips the sequence grant when the column owns none" do
      harness.grant_runtime_privileges!(:widgets)
      expect(sql).to include("GRANT SELECT, INSERT, UPDATE, DELETE")
      expect(sql).not_to include("ON SEQUENCE")
    end

    it "still honours an explicit sequence name" do
      harness.grant_runtime_privileges!(:widgets, sequence: :widgets_seq)
      expect(sql).to include(%(ON SEQUENCE "widgets_seq" TO app_runtime;))
    end
  end

  describe "#create_override_policy!" do
    before { harness.create_override_policy!(:widgets, predicate: "current_setting('app.admin') = 'on'") }

    it "layers a permissive ALL policy carrying the host's predicate" do
      expect(sql).to include(%(CREATE POLICY widgets_override_all ON "widgets" FOR ALL))
      expect(sql).to include(%(USING (current_setting('app.admin') = 'on')))
      expect(sql).to include(%(WITH CHECK (current_setting('app.admin') = 'on')))
    end
  end

  describe "#add_tenant_foreign_key!" do
    before { harness.add_tenant_foreign_key!(:line_items, :orders, column: :order_id) }

    it "keys the reference on the discriminator so it cannot cross tenants" do
      expect(sql).to include(%(FOREIGN KEY ("tenant_id", "order_id") REFERENCES "orders" ("tenant_id", "id")))
    end

    it "adds the composite UNIQUE the reference requires on the parent" do
      expect(sql).to include(%(ADD CONSTRAINT uq_orders_tenant_id UNIQUE ("tenant_id", "id")))
    end

    it "is idempotent — every constraint is guarded by an existence check" do
      expect(sql.scan("IF NOT EXISTS").length).to eq(2)
      expect(sql).to include("conrelid = to_regclass('orders')")
    end
  end
end
