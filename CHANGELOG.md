## [Unreleased]

## [0.3.0] - 2026-08-18

### Added

- `PgTenantRls.register_archetype(name) { |a| ... }` — declare an access archetype of your own.
  It is thereafter usable everywhere a built-in one is: applied, re-applied, pruned when a table
  changes archetype, and verified against a manifest. The expressions are written to the database
  unchanged; the gem does not parse, validate or rewrite them and never learns what a host
  function means. Until now a host with an access pattern of its own could only reimplement the
  mechanics beside the gem, and one consumer did — its `public_read` now means something this
  gem's does not.
- `a.discriminator false` / `a.discriminator true, nullable: true` in a registration — whether
  tables under the archetype carry the discriminator column and whether it admits null. These
  facts sat with the caller as one list per property; one consumer kept four of them and a fifth
  copy of the archetype list beside them, and the copy drifted through a single added archetype
  and took 197 of its examples down.
- `a.policy name: "existing_policy_name"` — an archetype can adopt policy names a schema already
  carries instead of requiring live objects to be renamed.
- `PgTenantRls::Inspector.identify(connection, table)` — which registered archetype a table's
  policies correspond to, or `nil`. The question asked when there is no manifest yet and an
  existing schema has to be inventoried. Policies no archetype claims are ignored rather than
  counted against the match, since an override is layered on top of an archetype by design.
- Specs for `PgTenantRls::Context`, which had none: nesting, restoring a context the caller set
  itself, the swap guard, and the aborted-transaction case below.

### Changed

- Inspection now distinguishes a policy belonging to **another registered archetype** from one
  belonging to **no** registered archetype. Both used to be reported as "unexpected policies",
  and they call for different answers: the first is a switch that did not finish, leaving the
  table under two archetypes at once combining with `OR`; the second is something enforced that
  no declaration accounts for, which may equally be a deliberate host override. Foreign policies
  are named with the archetype that claims them.
- The archetype list is no longer a constant. `Archetypes::POLICIES` and `Archetypes::METHODS`
  are replaced by a registry, and the archetypes this gem ships are registrations it makes for
  itself — the same door a host uses, so the mechanism cannot drift from the archetypes it was
  built for. Every `create_*_policy!` keeps its name, signature and behaviour.
- `apply_tenant_archetype!` adds the discriminator column when the archetype declares one and the
  table does not have it, the catalog being asked first so that a table already carrying it sees
  no statement at all. `ALTER TABLE` takes an `ACCESS EXCLUSIVE` lock whether or not it has
  anything to do, and this runs for every table on every reconcile.
- Applying or verifying an unregistered archetype raises naming the archetype and listing what is
  registered, rather than failing with a missing-method error naming an internal method.

### Fixed

- Redeclaring a permissive policy as restrictive altered it in place and left it combining with
  `OR` — widening access where the redeclaration asked to narrow it. `ALTER POLICY` can change
  neither the command nor the permissiveness ("the policy must be dropped and recreated"), and
  the rewrite compared only the command, because permissiveness was not something an archetype
  could state. It compares both now.
- `Inspector` demanded a discriminator column of every table, so a shared catalogue owned by
  nobody — the `reference` archetype, whose rows have no owner by design — was reported broken
  for being built exactly as declared. The expectation now comes from the archetype.
- A database error inside `Context.with_tenant` reached the caller as
  `PG::InFailedSqlTransaction` instead of the error that caused it. The restore in `ensure` ran a
  statement on a connection whose transaction had already failed, and raised from an `ensure`
  that failure replaces the exception on its way out — so the caller was told the transaction was
  aborted and never which write aborted it. The restore is skipped when the transaction has
  failed; `set_config(..., true)` is undone by the rollback that must follow anyway. Reported
  from a consumer, where a composite foreign key violation arrived unrecognizable.

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

- `create_reference_policy!(table, writable_when:)` — the shared-catalogue archetype:
  everyone reads, only an administrator writes. No discriminator and no tenant column; the
  rows belong to nobody, and what RLS adds here is the write side. Such tables are usually
  left with RLS off, at which point "shared" quietly also means "writable" — the only thing
  between a tenant and a `DELETE` is the `GRANT`, which is normally full. Shared and
  immutable are different properties, and leaving RLS off implies only the first. The
  predicate comes from the host; writes under a `BYPASSRLS` role are unaffected.
- `create_tenant_function!` — writes a `STABLE` SQL function returning the current tenant id
  and points the configuration at it, so DDL calls the function instead of inlining the GUC
  read. Without it the GUC name is part of the schema: it appears literally in every column
  `DEFAULT` and every policy predicate, PostgreSQL offering no indirection for a GUC name
  inside an expression, and a `DEFAULT` is baked when the migration runs — so a rename leaves
  older tables stamping `NULL`, which the very policy meant to protect them then rejects.
  With the function, a rename is one `CREATE OR REPLACE` and no table is touched.
- Assigning a configuration attribute twice with conflicting values now raises. Two components
  disagreeing about the tenant contour is not a preference being overridden — it is a
  disagreement that otherwise stays invisible until the second engine's tables turn out to
  read a GUC nobody sets. Re-declaring the same value is fine, since initializers can re-run.
- `apply_tenant_archetype!(table, archetype, **options)` — brings a table to exactly one
  archetype without ever leaving it unprotected. The usual pairing of `drop_tenant_policies!`
  with a `create_*_policy!` opens a window in which a table with RLS enabled has no policy at
  all and default-denies every row. On a live database that is worse than a lock: a blocked
  query eventually returns the truth, while a query slipping through the window returns an
  empty result that a cache is happy to keep. Here the archetype's policies are written
  first, and only then are policies of *other* archetypes removed. Policies this gem did not
  write are left alone, so a host override survives a reapply.
- `recreate_policy!` no longer issues `DROP POLICY IF EXISTS` when the catalog has just
  reported that no such policy exists.
- `enable_tenant_rls!` skips each `ALTER` whose flag is already set. PostgreSQL takes an
  `ACCESS EXCLUSIVE` lock even for a no-op `ENABLE ROW LEVEL SECURITY`: the statement is
  metadata-only and finishes in milliseconds at any table size, but acquiring the lock waits
  for every running query on the table and queues new ones behind it. On a reconcile that
  runs each deploy, a statement with nothing to change froze reads for as long as the slowest
  scan in flight. The two flags are checked independently — a table can be enabled without
  being forced, and skipping the `FORCE` on the strength of the `ENABLE` flag would silently
  leave the owner bypassing every policy.
- Policy writes prefer `ALTER POLICY` when a policy of that name and command already exists.
  `DROP` followed by `CREATE` left a window in which a table with RLS enabled had no policy at
  all and default-denied every row — invisible on a migration, an outage on a live reconcile.

## [0.1.0] - 2026-06-06

- Initial release
