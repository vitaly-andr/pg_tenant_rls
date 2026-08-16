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

    it "leaves policy_role nil, so policies stay role-agnostic even with runtime_role set" do
      described_class.configure { |c| c.runtime_role = "app_runtime" }

      expect(described_class.config.policy_role).to be_nil
    end
  end

  describe "conflicting configuration" do
    it "refuses a second, different value — two components disagreeing about the contour" do
      described_class.configure { |c| c.guc = "app.current_team_id" }

      expect { described_class.configure { |c| c.guc = "app.current_crm_id" } }
        .to raise_error(PgTenantRls::Error, /one tenant contour per process/)
    end

    it "allows re-declaring the same value, since initializers can run twice" do
      described_class.configure { |c| c.discriminator = :team_id }

      expect { described_class.configure { |c| c.discriminator = :team_id } }.not_to raise_error
    end

    it "does not treat the built-in default as a declaration" do
      expect { described_class.configure { |c| c.guc = "app.current_team_id" } }.not_to raise_error
    end

    it "starts over after reset_config!" do
      described_class.configure { |c| c.guc = "app.a" }
      described_class.reset_config!

      expect { described_class.configure { |c| c.guc = "app.b" } }.not_to raise_error
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

    it "calls the indirection function instead, once one is configured" do
      described_class.config.tenant_function = "public.current_tenant_id"

      expect(described_class.tenant_id_sql).to eq("public.current_tenant_id()")
    end

    it "keeps guc_expression literal, so the function body does not call itself" do
      described_class.configure { |c| c.guc = "app.current_team_id" }
      described_class.config.tenant_function = "public.current_tenant_id"

      expect(described_class.guc_expression).to include("current_setting('app.current_team_id'")
    end
  end
end
