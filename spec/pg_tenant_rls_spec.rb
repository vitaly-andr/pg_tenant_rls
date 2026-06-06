# frozen_string_literal: true

RSpec.describe PgTenantRls do
  after { described_class.reset_config! }

  it "has a version number" do
    expect(PgTenantRls::VERSION).not_to be_nil
  end

  describe ".configure" do
    it "sets the contract values" do
      described_class.configure do |c|
        c.guc           = "app.current_team_id"
        c.discriminator = :team_id
        c.key_type      = :bigint
        c.runtime_role  = "app_runtime"
      end

      expect(described_class.config.guc).to eq("app.current_team_id")
      expect(described_class.config.discriminator).to eq(:team_id)
      expect(described_class.config.key_type).to eq(:bigint)
      expect(described_class.config.runtime_role).to eq("app_runtime")
    end

    it "defaults to a generic tenant contract" do
      expect(described_class.config.guc).to eq("app.current_tenant_id")
      expect(described_class.config.discriminator).to eq(:tenant_id)
    end
  end

  describe ".tenant_id_sql" do
    it "builds a NULL-on-empty cast from the configured GUC and key type" do
      described_class.configure do |c|
        c.guc      = "app.current_team_id"
        c.key_type = :bigint
      end

      expect(described_class.tenant_id_sql)
        .to eq("NULLIF(current_setting('app.current_team_id', true), '')::bigint")
    end

    it "escapes single quotes in the GUC name" do
      described_class.configure { |c| c.guc = "a'b" }

      expect(described_class.tenant_id_sql).to include("'a''b'")
    end
  end
end
