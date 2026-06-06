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
  c.runtime_role  = "app_runtime"           # NOSUPERUSER/NOBYPASSRLS role used at runtime
end
```

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

A shared catalog (everyone reads, owner writes):

```ruby
create_public_read_owner_write_policy! :products, owner_column: :owner_tenant_id
```

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

## Development

After checking out the repo, run `bin/setup` to install dependencies, then `rake spec`.

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).