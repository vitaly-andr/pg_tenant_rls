# frozen_string_literal: true

# Behaviour, not text. Every assertion here runs against a live PostgreSQL as an
# unprivileged role, because that is the only configuration in which policies are
# actually consulted.
RSpec.describe "tenant isolation", :database do
  let(:runtime) { TestDatabase.runtime }
  let(:owner) { TestDatabase.owner }
  let(:migration) { TestDatabase.runner }

  def runtime_count(table)
    runtime.select_value("SELECT count(*) FROM #{table}").to_i
  end

  before do
    PgTenantRls.configure do |c|
      c.guc = "app.current_tenant_id"
      c.discriminator = :tenant_id
      c.key_type = :bigint
      c.runtime_role = TestDatabase::RUNTIME_ROLE
    end
  end

  after { PgTenantRls.reset_config! }

  describe "the harness itself — without this the whole suite is meaningless" do
    it "runs isolation assertions as a role policies actually bind to" do
      expect(PgTenantRls::Inspector.enforced_for_current_role?(runtime)).to be(true)
    end

    it "would report the owner as unenforced, which is why the owner is not used here" do
      expect(PgTenantRls::Inspector.enforced_for_current_role?(owner)).to be(false)
    end
  end

  describe "the tenant archetype" do
    before do
      TestDatabase.reset_table!("widgets", "name text")
      migration.add_tenant_column!(:widgets)
      migration.enable_tenant_rls!(:widgets)
      migration.create_tenant_policy!(:widgets)
      TestDatabase.as_tenant(1) { runtime.execute("INSERT INTO widgets (name) VALUES ('one')") }
      TestDatabase.as_tenant(2) { runtime.execute("INSERT INTO widgets (name) VALUES ('two')") }
    end

    it "stamps the discriminator from the GUC without the insert mentioning it" do
      TestDatabase.as_tenant(1) do
        expect(runtime.select_value("SELECT tenant_id FROM widgets").to_i).to eq(1)
      end
    end

    it "hides other tenants' rows" do
      TestDatabase.as_tenant(1) { expect(runtime_count("widgets")).to eq(1) }
      TestDatabase.as_tenant(2) { expect(runtime_count("widgets")).to eq(1) }
    end

    it "refuses to write a row belonging to another tenant" do
      TestDatabase.as_tenant(1) do
        expect { runtime.execute("INSERT INTO widgets (name, tenant_id) VALUES ('x', 2)") }
          .to raise_error(ActiveRecord::StatementInvalid, /row-level security/)
      end
    end

    it "cannot update or delete a row it cannot see" do
      TestDatabase.as_tenant(1) do
        runtime.execute("UPDATE widgets SET name = 'hijacked'")
        runtime.execute("DELETE FROM widgets WHERE true")
      end
      TestDatabase.as_tenant(2) do
        expect(runtime.select_value("SELECT name FROM widgets")).to eq("two")
      end
    end

    it "returns nothing at all with no tenant context — fail-closed" do
      TestDatabase.without_tenant { expect(runtime_count("widgets")).to eq(0) }
    end
  end

  describe "the public_catalog archetype — the one that fails OPEN" do
    before do
      TestDatabase.reset_table!("catalog_items", "name text")
      migration.add_tenant_column!(:catalog_items, null: true)
      migration.enable_tenant_rls!(:catalog_items)
      migration.create_public_catalog_policy!(:catalog_items)
      TestDatabase.as_tenant(1) { runtime.execute("INSERT INTO catalog_items (name) VALUES ('one')") }
      TestDatabase.as_tenant(2) { runtime.execute("INSERT INTO catalog_items (name) VALUES ('two')") }
    end

    it "shows every tenant's rows when no context is set — by design, and the risk" do
      TestDatabase.without_tenant { expect(runtime_count("catalog_items")).to eq(2) }
    end

    it "narrows to own rows once a context is set" do
      TestDatabase.as_tenant(1) { expect(runtime_count("catalog_items")).to eq(1) }
    end

    it "still refuses cross-tenant writes even with no context" do
      TestDatabase.without_tenant do
        expect { runtime.execute("INSERT INTO catalog_items (name, tenant_id) VALUES ('x', 2)") }
          .to raise_error(ActiveRecord::StatementInvalid, /row-level security/)
      end
    end
  end

  describe "#add_tenant_foreign_key! — closing the hole integrity checks leave open" do
    before do
      TestDatabase.reset_table!("orders", "label text")
      TestDatabase.reset_table!("line_items", "order_id bigint, label text")
      %i[orders line_items].each do |table|
        migration.add_tenant_column!(table)
        migration.enable_tenant_rls!(table)
        migration.create_tenant_policy!(table)
      end
      migration.add_tenant_foreign_key!(:line_items, :orders, column: :order_id)
      TestDatabase.as_tenant(2) { runtime.execute("INSERT INTO orders (label) VALUES ('theirs')") }
    end

    it "rejects a reference to another tenant's row, which a plain FK would accept" do
      foreign_id = owner.select_value("SELECT id FROM orders WHERE label = 'theirs'")
      TestDatabase.as_tenant(1) do
        expect { runtime.execute("INSERT INTO line_items (order_id, label) VALUES (#{foreign_id}, 'x')") }
          .to raise_error(ActiveRecord::StatementInvalid, /foreign key|violates/i)
      end
    end

    it "accepts a reference within the same tenant" do
      TestDatabase.as_tenant(1) do
        runtime.execute("INSERT INTO orders (label) VALUES ('mine')")
        own_id = runtime.select_value("SELECT id FROM orders WHERE label = 'mine'")
        runtime.execute("INSERT INTO line_items (order_id, label) VALUES (#{own_id}, 'ok')")
        expect(runtime_count("line_items")).to eq(1)
      end
    end
  end

  describe "policy rewrite — ALTER leaves the policy in place" do
    before do
      TestDatabase.reset_table!("rewritten", "name text")
      migration.add_tenant_column!(:rewritten)
      migration.enable_tenant_rls!(:rewritten)
      migration.create_tenant_policy!(:rewritten)
    end

    def policy_oid
      owner.select_value("SELECT oid FROM pg_policy WHERE polname = 'rewritten_tenant_all'")
    end

    it "keeps the very same policy object when the archetype is reapplied" do
      before_oid = policy_oid
      migration.create_tenant_policy!(:rewritten)
      expect(policy_oid).to eq(before_oid)
    end

    it "replaces the policy when the command changes, since ALTER cannot" do
      before_oid = policy_oid
      migration.send(:recreate_policy!, :rewritten, declaration(command: "SELECT", using: "true"))
      expect(policy_oid).not_to eq(before_oid)
    end

    # The other half of the same documented rule: "To change other properties of a policy,
    # such as the command to which it applies or whether it is permissive or restrictive,
    # the policy must be dropped and recreated." Altering in place instead would leave a
    # policy declared restrictive still combining with OR — widening where the
    # redeclaration asked to narrow. The oid is what distinguishes the two; the resulting
    # predicate text is identical either way.
    it "replaces the policy when permissiveness changes, for the same reason" do
      before_oid = policy_oid
      migration.send(:recreate_policy!, :rewritten,
                     declaration(command: "ALL", permissive: false, using: "true"))
      expect(policy_oid).not_to eq(before_oid)
      expect(owner.select_value("SELECT polpermissive FROM pg_policy WHERE oid = #{policy_oid}"))
        .to be(false)
    end

    def declaration(**attributes)
      PgTenantRls::PolicyDeclaration.new(name: "rewritten_tenant_all", **attributes)
    end
  end

  describe "#enable_tenant_rls! against the real catalog" do
    before { TestDatabase.reset_table!("flagged", "name text") }

    def flags
      owner.select_value(
        "SELECT relrowsecurity::int::text || relforcerowsecurity::int::text " \
        "FROM pg_class WHERE oid = to_regclass('flagged')"
      )
    end

    it "reaches enabled-and-forced from a table with neither" do
      expect(flags).to eq("00")
      migration.enable_tenant_rls!(:flagged)
      expect(flags).to eq("11")
    end

    it "leaves the state untouched when called again — the reconcile case" do
      migration.enable_tenant_rls!(:flagged)
      migration.enable_tenant_rls!(:flagged)
      expect(flags).to eq("11")
    end

    # PostgreSQL takes ACCESS EXCLUSIVE even for a no-op ENABLE, so the point is not that
    # the second call is harmless — it is that it must not run at all.
    it "issues no ALTER on the second call" do
      migration.enable_tenant_rls!(:flagged)
      statements = []
      recorder = TestDatabase::Runner.new(owner)
      recorder.define_singleton_method(:execute) { |sql| statements << sql }
      recorder.enable_tenant_rls!(:flagged)
      expect(statements).to be_empty
    end
  end

  describe "#apply_tenant_archetype! against the real catalog" do
    before do
      TestDatabase.reset_table!("switched", "name text")
      migration.add_tenant_column!(:switched, null: true)
      migration.enable_tenant_rls!(:switched)
    end

    def policy_names
      owner.select_values("SELECT polname FROM pg_policy WHERE polrelid = to_regclass('switched') ORDER BY polname")
    end

    it "switches archetype, leaving only the new one's policies" do
      migration.apply_tenant_archetype!(:switched, :public_catalog)
      expect(policy_names).to all(include("catalog"))

      migration.apply_tenant_archetype!(:switched, :tenant)
      expect(policy_names).to eq(["switched_tenant_all"])
    end

    it "keeps a host policy the gem never wrote — drop_tenant_policies! would not" do
      migration.apply_tenant_archetype!(:switched, :tenant)
      migration.create_override_policy!(:switched, predicate: "current_setting('app.admin', true) = 'on'")
      migration.apply_tenant_archetype!(:switched, :tenant)
      expect(policy_names).to include("switched_override_all")
    end

    # Pruning used to know only the gem's own names, so a host archetype's policies
    # survived every switch away from it — the table ended up under two archetypes at once,
    # combining with OR.
    it "prunes a host-registered archetype's policies too" do
      PgTenantRls.register_archetype(:audited) do |a|
        a.discriminator false
        a.policy :audited_select, command: "SELECT", using: "true"
      end

      migration.apply_tenant_archetype!(:switched, :audited)
      expect(policy_names).to eq(["switched_audited_select"])

      migration.apply_tenant_archetype!(:switched, :tenant)
      expect(policy_names).to eq(["switched_tenant_all"])
    ensure
      PgTenantRls::Archetypes.reset!
    end

    # The reason this method exists: no moment in which the table has RLS and no policy.
    it "never leaves the table without a policy while switching" do
      migration.apply_tenant_archetype!(:switched, :public_catalog)
      statements = []
      recorder = TestDatabase::Runner.new(owner)
      recorder.define_singleton_method(:execute) { |sql| statements << sql }
      recorder.apply_tenant_archetype!(:switched, :tenant)

      first_drop = statements.index { |s| s.start_with?("DROP POLICY") }
      first_write = statements.index { |s| s.match?(/\A(CREATE|ALTER) POLICY/) }
      expect(first_write).to be < first_drop
    end
  end

  # US1, proven where it counts. The gem contains no author_id, no app.current_author_id
  # and no :authored — all of it arrives at runtime, and the rows a query can reach are
  # decided by PostgreSQL under a role that cannot bypass a policy.
  describe "an archetype the host registered, against the real catalog" do
    author_sql = "NULLIF(current_setting('app.current_author_id', true), '')::bigint"

    before do
      PgTenantRls.register_archetype(:authored) do |a|
        a.discriminator false
        a.policy :authored_select, command: "SELECT", using: "author_id = #{author_sql}"
        a.policy :authored_insert, command: "INSERT", check: "author_id = #{author_sql}"
      end

      TestDatabase.reset_table!("notes", "body text, author_id bigint")
      migration.enable_tenant_rls!(:notes)
      migration.apply_tenant_archetype!(:notes, :authored)
      owner.execute("INSERT INTO notes (body, author_id) VALUES ('mine', 1), ('theirs', 2)")
    end

    after { PgTenantRls::Archetypes.reset! }

    def as_author(id)
      runtime.execute("SELECT set_config('app.current_author_id', '#{id}', false)")
      yield
    ensure
      runtime.execute("SELECT set_config('app.current_author_id', '', false)")
    end

    def policy_oid(name)
      owner.select_value("SELECT oid FROM pg_policy WHERE polname = '#{name}'")
    end

    it "reaches exactly the rows the host's own predicate admits" do
      as_author(1) { expect(runtime_count("notes")).to eq(1) }
      as_author(2) { expect(runtime_count("notes")).to eq(1) }
    end

    it "refuses a write the declaration's WITH CHECK does not admit" do
      as_author(1) do
        expect { runtime.execute("INSERT INTO notes (body, author_id) VALUES ('x', 2)") }
          .to raise_error(ActiveRecord::StatementInvalid, /row-level security/)
      end
    end

    # Closed by default, like every archetype but public_catalog: with no context the
    # predicate is NULL, and NULL is not true.
    it "shows nothing at all when the host's context is missing" do
      expect(runtime_count("notes")).to eq(0)
    end

    it "carries no discriminator column, since the declaration asked for none" do
      expect(owner.select_values(<<~SQL)).to be_empty
        SELECT attname FROM pg_attribute
        WHERE attrelid = to_regclass('notes') AND attname = 'tenant_id' AND NOT attisdropped
      SQL
    end

    # US3 for a registered archetype: it inherits the mechanics rather than approximating
    # them. The oid is the only thing that tells altering apart from recreating — the
    # predicate text, and every row reachable through it, come out the same either way.
    it "is altered in place on re-application, never dropped and recreated" do
      before_oid = policy_oid("notes_authored_select")
      migration.apply_tenant_archetype!(:notes, :authored)
      expect(policy_oid("notes_authored_select")).to eq(before_oid)
    end

    it "issues no ALTER TABLE on re-application either, the flags already being set" do
      statements = []
      recorder = TestDatabase::Runner.new(owner)
      recorder.define_singleton_method(:execute) { |sql| statements << sql }
      recorder.enable_tenant_rls!(:notes)
      expect(statements).to be_empty
    end

    it "is verified against a manifest like any archetype the gem ships" do
      expect(PgTenantRls::Inspector.verify!(owner, manifest: { notes: :authored })).to be(true)
    end
  end

  describe "#create_tenant_function! — the GUC name out of the schema" do
    after { PgTenantRls.config.tenant_function = nil }

    before do
      migration.create_tenant_function!(name: "spec_current_tenant")
      TestDatabase.reset_table!("via_function", "name text")
      migration.add_tenant_column!(:via_function)
      migration.enable_tenant_rls!(:via_function)
      migration.create_tenant_policy!(:via_function)
    end

    it "writes a call, not the GUC read, into the DDL" do
      default = owner.select_value(<<~SQL)
        SELECT pg_get_expr(d.adbin, d.adrelid) FROM pg_attribute a
        JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
        WHERE a.attrelid = to_regclass('via_function') AND a.attname = 'tenant_id'
      SQL
      expect(default).to include("spec_current_tenant")
      expect(default).not_to include("current_setting")
    end

    it "isolates exactly as the inlined form does" do
      TestDatabase.as_tenant(1) { runtime.execute("INSERT INTO via_function (name) VALUES ('one')") }
      TestDatabase.as_tenant(2) { runtime.execute("INSERT INTO via_function (name) VALUES ('two')") }

      TestDatabase.as_tenant(1) { expect(runtime_count("via_function")).to eq(1) }
      TestDatabase.without_tenant { expect(runtime_count("via_function")).to eq(0) }
    end

    # The point of the indirection: renaming the GUC touches one function body, and every
    # table's DEFAULT and every policy follow without being rewritten.
    it "follows a GUC rename through CREATE OR REPLACE alone" do
      TestDatabase.as_tenant(7) { runtime.execute("INSERT INTO via_function (name) VALUES ('seven')") }
      owner.execute(<<~SQL)
        CREATE OR REPLACE FUNCTION public.spec_current_tenant() RETURNS bigint
        LANGUAGE sql STABLE AS $$ SELECT NULLIF(current_setting('app.renamed_guc', true), '')::bigint $$;
      SQL

      runtime.execute("SELECT set_config('app.renamed_guc', '7', false)")
      expect(runtime_count("via_function")).to eq(1)
    ensure
      runtime.execute("SELECT set_config('app.renamed_guc', '', false)")
      owner.execute(<<~SQL)
        CREATE OR REPLACE FUNCTION public.spec_current_tenant() RETURNS bigint
        LANGUAGE sql STABLE AS $$ SELECT NULLIF(current_setting('app.current_tenant_id', true), '')::bigint $$;
      SQL
    end
  end

  describe "the reference archetype — the hole an RLS-less shared table leaves open" do
    let(:admin) { "COALESCE(NULLIF(current_setting('app.is_super_admin', true), '')::boolean, false)" }

    before do
      TestDatabase.reset_table!("shared_refs", "name text")
      migration.enable_tenant_rls!(:shared_refs)
      migration.create_reference_policy!(:shared_refs, writable_when: admin)
      owner.execute("INSERT INTO shared_refs (name) VALUES ('canon')")
    end

    after { runtime.execute("SELECT set_config('app.is_super_admin', '', false)") }

    it "is readable without any tenant context" do
      TestDatabase.without_tenant { expect(runtime_count("shared_refs")).to eq(1) }
    end

    it "is readable inside a tenant context too, without belonging to one" do
      TestDatabase.as_tenant(1) { expect(runtime_count("shared_refs")).to eq(1) }
    end

    it "refuses a write from an ordinary tenant — the rule that was unenforced before" do
      TestDatabase.as_tenant(1) do
        expect { runtime.execute("INSERT INTO shared_refs (name) VALUES ('invented')") }
          .to raise_error(ActiveRecord::StatementInvalid, /row-level security/)
      end
    end

    it "refuses deletion by a tenant, which a GRANT alone would have allowed" do
      TestDatabase.as_tenant(1) do
        runtime.execute("DELETE FROM shared_refs WHERE true")
        expect(runtime_count("shared_refs")).to eq(1)
      end
    end

    it "admits the administrator" do
      runtime.execute("SELECT set_config('app.is_super_admin', 'true', false)")
      runtime.execute("INSERT INTO shared_refs (name) VALUES ('added by admin')")
      expect(runtime_count("shared_refs")).to eq(2)
    end
  end

  describe "Inspector against the live catalog" do
    before do
      TestDatabase.reset_table!("inspected", "name text")
      migration.add_tenant_column!(:inspected)
      migration.enable_tenant_rls!(:inspected)
      migration.create_tenant_policy!(:inspected)
    end

    let(:report) { PgTenantRls::Inspector.call(owner, tables: ["inspected"]).first }

    it "reads RLS and FORCE flags from pg_class" do
      expect(report[:rls_enabled]).to be(true)
      expect(report[:rls_forced]).to be(true)
    end

    it "reads the policy with its command, permissiveness and expressions" do
      policy = report[:policies].first
      expect(policy[:name]).to eq("inspected_tenant_all")
      expect(policy[:command]).to eq("ALL")
      expect(policy[:permissive]).to be(true)
      expect(policy[:roles]).to eq(["public"])
      expect(policy[:using]).to include("current_setting")
    end

    it "reads the discriminator with its type, nullability and GUC default" do
      expect(report[:discriminator][:type]).to eq("bigint")
      expect(report[:discriminator][:not_null]).to be(true)
      expect(report[:discriminator][:default]).to include("app.current_tenant_id")
    end

    it "passes verify! for a correctly declared manifest" do
      expect(PgTenantRls::Inspector.verify!(owner, manifest: { inspected: :tenant })).to be(true)
    end

    it "fails verify! when the manifest declares a different archetype" do
      expect { PgTenantRls::Inspector.verify!(owner, manifest: { inspected: :public_catalog }) }
        .to raise_error(PgTenantRls::Error, /missing policies|unexpected policies/)
    end

    it "catches a table inside the perimeter that the manifest never declares" do
      problems = PgTenantRls::Inspector.audit(owner, manifest: {}, prefixes: ["inspected"])
      expect(problems).to include(a_string_matching(/inspected: in the perimeter but absent/))
    end

    it "reports foreign keys that omit the discriminator" do
      owner.execute("ALTER TABLE inspected ADD COLUMN other_id bigint REFERENCES inspected (id);")
      expect(report[:foreign_keys_without_discriminator]).not_to be_empty
    end
  end
end
