# PgTenantRls

PostgreSQL Row-Level-Security (RLS) multitenancy for ActiveRecord.

`pg_tenant_rls` enforces tenant isolation **in the database** rather than in Ruby. It gives you:

- a **transaction-scoped tenant context** via `SET LOCAL` — PgBouncer transaction-pool friendly;
- a **migration DSL** for tenant and public-read/owner-write policies, with `FORCE ROW LEVEL SECURITY`;
- **runtime-role provisioning** (an unprivileged `NOBYPASSRLS` role) so policies are actually enforced.

It is host-agnostic: you configure the session GUC, the discriminator column, the key type, and the
runtime role. The gem has no notion of teams, organizations, or any particular tenant model.

## Installation

```ruby
gem "pg_tenant_rls"
```

## Configuration

```ruby
# config/initializers/pg_tenant_rls.rb
PgTenantRls.configure do |c|
  c.guc           = "app.current_tenant_id" # GUC your app sets per request/job
  c.discriminator = :tenant_id              # discriminator column on tenant-scoped tables
  c.key_type      = :bigint                 # SQL type of the tenant key
  c.runtime_role  = "app_runtime"           # NOSUPERUSER/NOBYPASSRLS role, target of GRANTs
end
```

Configure from the **host**, once. The configuration is process-global on purpose: the tenant
context belongs to the database session, not to a Ruby object, so a per-consumer configuration
would not make the database multi-contour — each consumer would merely believe it had its own
while writing to the same session. Engines mounted in a host inherit its GUC, discriminator and
key type; they should not call `configure` themselves.

Two settings name roles, and they are not the same one:

- `runtime_role` — who receives `GRANT`s. Required by `RoleProvisioner`.
- `policy_role` — the `TO` clause on policies. Defaults to `nil`, and usually should stay there:
  a policy without `TO` applies to `PUBLIC`, while `TO <role>` adds nothing to isolation and
  costs portability (a schema load fails where the role is absent) and safety of failure (a role
  not listed sees zero rows).

**The GUC name becomes part of your schema.** It is written literally into every column `DEFAULT`
and every policy predicate, because PostgreSQL offers no indirection for a GUC name inside an
expression. Changing it later means rewriting both — and note that a `DEFAULT` is baked at
migration time, so tables created by an ordinary migration will not pick up a new GUC on their
own.

## Migrations

```ruby
class AddTenancyToWidgets < ActiveRecord::Migration[7.1]
  def up
    add_tenant_column!        :widgets   # tenant_id bigint, DB DEFAULT from the GUC, NOT NULL
    enable_tenant_rls!        :widgets   # ENABLE + FORCE ROW LEVEL SECURITY
    create_tenant_policy!     :widgets   # row visible/writable iff tenant_id = current tenant
    grant_runtime_privileges! :widgets   # GRANT DML to the runtime role
  end

  def down
    drop_tenant_policies! :widgets
    disable_tenant_rls!   :widgets
    remove_column :widgets, :tenant_id
  end
end
```

Other access archetypes:

```ruby
# Own rows + global defaults (tenant_id IS NULL); writes own only:
create_shared_default_policy! :price_types

# Published rows are world-readable (gated on a domain boolean column) + own; writes own only:
create_public_read_policy! :products, published_column: :published

# Same, but the publish flag lives in a separate register rather than on the table:
create_gated_read_policy! :products, gate: { table: :publications, fk: :product_id }

# No tenant context → every row (a public storefront); with one → own rows only:
create_public_catalog_policy! :products
```

Mind how each one fails when the tenant context is missing. `tenant`, `shared_default`,
`public_read` and `gated_read` return zero rows — a loud failure. `public_catalog` returns
**everything**, by design, because a storefront has to work without a tenant. That difference is
why "the table has a policy" is not a check worth making.

## Foreign keys

Referential integrity checks bypass row security ([PostgreSQL,
"Row Security Policies"](https://www.postgresql.org/docs/current/ddl-rowsecurity.html)). A plain
`FOREIGN KEY (order_id) REFERENCES orders (id)` therefore accepts another tenant's row: invisible,
but present — and the difference between a violation and a success is an existence oracle over
every id in the table. Key the reference on the discriminator too:

```ruby
add_tenant_foreign_key! :line_items, :orders, column: :order_id
# → UNIQUE (tenant_id, id) on orders, then
#   FOREIGN KEY (tenant_id, order_id) REFERENCES orders (tenant_id, id)
```

For the `tenant` archetype only: `shared_default` parents carry NULL discriminators, and the
public/gated archetypes reference other tenants on purpose.

## Checking what the database actually holds

```ruby
PgTenantRls::Inspector.call(connection, prefixes: [Crm.table_name_prefix])
PgTenantRls::Inspector.verify!(connection, manifest: { crm_deals: :tenant, crm_products: :public_catalog })
```

`call` reports RLS and FORCE flags, every policy with its command, permissiveness, roles and
expressions, the discriminator column, and foreign keys that omit the discriminator. `verify!`
checks that against a manifest you declare and raises on any mismatch.

Declare the perimeter — the gem will not guess it. It cannot recognize its own tables: a host
writing the same predicate by hand produces a byte-identical `DEFAULT`, and a policy name is a
hint rather than metadata, since the name survives while its predicate changes. When you pass
`prefixes:`, take them from `Module.table_name_prefix` rather than a literal — `isolate_namespace`
rewrites an engine's prefix to include the host's own once ActiveRecord loads, so a hardcoded
`"crm_"` can silently match nothing.

## Setting the tenant at runtime

```ruby
PgTenantRls::Context.with_tenant(tenant.id) do
  Widget.create!(name: "scoped")   # tenant_id stamped by the DB DEFAULT; RLS filters reads
end

PgTenantRls::Context.without_tenant do
  # explicitly outside any tenant (system work)
end
```

`with_tenant` refuses to switch to a *different* tenant inside an active context
(`PgTenantRls::Context::SwapError`); pass `allow_swap: true` when that is intentional.

## Provisioning the runtime role

```ruby
PgTenantRls::RoleProvisioner.create_role!(connection)  # before schema load
PgTenantRls::RoleProvisioner.grant!(connection)        # after schema load
```

Run provisioning as an owner/superuser. **RLS is only enforced under a `NOBYPASSRLS`
role** — a superuser (or a table owner without `FORCE`) bypasses every policy, so
isolation tests must connect as the runtime role or they will pass for the wrong reason.
`PgTenantRls::Inspector.enforced_for_current_role?(connection)` answers that directly.

## Development

After checking out the repo, run `bin/setup` to install dependencies, then `rake spec`.

The suite has two halves. Unit specs capture the SQL each helper would run and need nothing
but Ruby. Isolation specs (`spec/isolation_spec.rb`, tagged `:database`) run against a real
PostgreSQL **as an unprivileged role** — they create a `pg_tenant_rls_test` database and a
`NOSUPERUSER`/`NOBYPASSRLS` role, then check that tenants genuinely cannot see or write each
other's rows. Without that role the specs would pass with RLS switched off entirely, so the
role is the test, not a detail of its setup.

Point them at your database with `PGHOST`, `PGPORT`, `PGUSER`, `PGPASSWORD` (defaults:
`localhost:5433`, user `spree`). With no database reachable they skip with a reason rather
than fail — a skipped isolation suite proves nothing, and should say so.

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).