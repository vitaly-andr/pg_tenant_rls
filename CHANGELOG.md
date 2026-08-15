## [Unreleased]

## [0.2.0] - 2026-08-14

### Breaking

- Policies no longer take their `TO` clause from `config.runtime_role`. That setting is now
  the GRANT target only; the policy binding moved to the new `config.policy_role`, which
  defaults to `nil`. A policy without `TO` applies to `PUBLIC`, so this is the safer and more
  portable default: `TO <role>` adds nothing to isolation, makes a table default-deny for any
  role not listed, and breaks schema loads where the role does not exist. Hosts that really
  want role-bound policies should set `policy_role` or pass `role:` explicitly.

### Fixed

- `drop_tenant_policies!` resolved tables by bare name, so it collected policies of same-named
  tables in other schemas. Identity now goes through `to_regclass` against `pg_policy`.
- `grant_runtime_privileges!` composed the sequence name as `"<table>_id_seq"`, which breaks on a
  non-default primary key and after a table rename (a rename does not rename the sequence). The
  owning sequence is now resolved with `pg_get_serial_sequence`; pass `sequence:` to override.

### Added

- `PgTenantRls::Inspector` — read-only inspection of isolation state against a live database:
  RLS/FORCE flags, every policy with its command, permissiveness, roles and expressions, the
  discriminator column, and foreign keys that omit the discriminator. `verify!` checks the
  perimeter against a declared `{ table => archetype }` manifest, and
  `enforced_for_current_role?` reports whether policies bind at all under the current role.
- `add_tenant_foreign_key!` — composite foreign key `(discriminator, column)` referencing
  `(discriminator, key)`, plus the composite `UNIQUE` it requires. Foreign key checks bypass row
  security, so a plain reference can point at another tenant's row and act as an existence
  oracle. For the `tenant` archetype only.
- `create_override_policy!` — permissive policy layered over an archetype, carrying a predicate
  the host supplies (the gem stays host-agnostic).
- Under Rails, a boot-time warning when another module has taken over this gem's migration
  helper names in `ActiveRecord::Migration`.
- Isolation specs against a live PostgreSQL, run as a `NOSUPERUSER`/`NOBYPASSRLS` role: two
  tenants that cannot see or write each other's rows, `tenant` returning nothing without a
  context while `public_catalog` returns everything, a composite foreign key rejecting another
  tenant's parent, and `Inspector` read back against the real catalog. Until now the suite only
  checked the text of the SQL it would have run, which is why the gem was marked not
  release-ready.
- `audit`/`verify!` accept `prefixes:` to catch the opposite mistake from a wrong archetype: a
  table that exists inside the perimeter but is missing from the manifest. Without it a
  forgotten table is simply never queried, so a check for "every table is declared" would be
  verifying itself.

### Changed

- Policy writes prefer `ALTER POLICY` when a policy of that name and command already exists.
  `DROP` followed by `CREATE` left a window in which a table with RLS enabled had no policy at
  all and default-denied every row — invisible on a migration, an outage on a live reconcile.

## [0.1.0] - 2026-06-06

- Initial release
