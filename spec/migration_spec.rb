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
      attr_accessor :existing_command, :sequence_name

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
        return [@existing_command].compact if sql.include?("polcmd")
        return [@sequence_name].compact if sql.include?("pg_get_serial_sequence")

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

  describe "#add_tenant_column!" do
    before { harness.add_tenant_column!(:widgets) }

    it "is idempotent (ADD COLUMN IF NOT EXISTS) with a DB DEFAULT from the GUC" do
      expect(sql).to include(%(ADD COLUMN IF NOT EXISTS "tenant_id" bigint DEFAULT #{guc_cast} NOT NULL))
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
      harness.existing_command = "*"
      harness.create_tenant_policy!(:widgets)
      expect(sql).to include(%(ALTER POLICY widgets_tenant_all ON "widgets" TO PUBLIC))
      expect(sql).not_to include("DROP POLICY")
      expect(sql).not_to include("CREATE POLICY")
    end

    it "spells out TO PUBLIC so a stale role binding is cleared, not left behind" do
      harness.existing_command = "*"
      harness.create_tenant_policy!(:widgets)
      expect(sql).to include("TO PUBLIC")
    end

    it "falls back to DROP + CREATE when the command differs" do
      harness.existing_command = "r" # SELECT, but the archetype wants ALL
      harness.create_tenant_policy!(:widgets)
      expect(sql).to include("DROP POLICY IF EXISTS widgets_tenant_all")
      expect(sql).to include("CREATE POLICY widgets_tenant_all")
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
