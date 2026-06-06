# frozen_string_literal: true

# Unit-level check of the migration DSL: a harness captures the SQL that each
# archetype would execute, stubbing ActiveRecord quoting. No database required.
RSpec.describe PgTenantRls::Migration do
  let(:harness) do
    Class.new do
      include PgTenantRls::Migration

      attr_reader :executed

      def initialize
        super
        @executed = []
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

      def select_values(_sql)
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

    it "creates an ALL policy scoped to the configured role" do
      expect(sql).to include(%(CREATE POLICY widgets_tenant_all ON "widgets" FOR ALL TO app_runtime))
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
end
