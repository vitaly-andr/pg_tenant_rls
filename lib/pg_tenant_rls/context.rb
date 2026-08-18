# frozen_string_literal: true

module PgTenantRls
  # Transaction-scoped tenant context via SET LOCAL (set_config(..., true)). This is
  # PgBouncer transaction-pool friendly, unlike connection-checkout based approaches.
  # The previous context is saved and restored, so nested .with calls compose.
  module Context
    # Raised on an attempt to switch to a DIFFERENT tenant inside an active context —
    # defense in depth on top of RLS (surfaces a bug before a policy silently returns
    # zero rows).
    class SwapError < PgTenantRls::Error; end

    # PQTRANS_INERROR. Written out rather than referenced through PG::Connection because
    # the pg gem is not a dependency of this one: the only runtime dependency is
    # ActiveRecord, and which driver sits underneath it is the host's business.
    PG_TRANSACTION_IN_ERROR = 3

    # Wrap a block in a tenant context.
    #   PgTenantRls::Context.with_tenant(5) { ... }
    #   PgTenantRls::Context.with_tenant(5, "app.current_user_id" => 3) { ... }
    def self.with_tenant(tenant_id, allow_swap: false, connection: nil, **extra, &block)
      vars = { PgTenantRls.config.guc => tenant_id }
      extra.each { |guc, value| vars[guc.to_s] = value }
      with(vars, allow_swap: allow_swap, connection: connection, &block)
    end

    # Explicitly run outside any tenant (personal/system); clears the tenant GUC.
    # allow_swap is implied because leaving a tenant is safe (you see less, not more).
    def self.without_tenant(connection: nil, &block)
      with({ PgTenantRls.config.guc => nil }, allow_swap: true, connection: connection, &block)
    end

    # Low-level primitive: vars = { guc_name => value, ... }.
    def self.with(vars, allow_swap: false, connection: nil, &block)
      conn = connection || ActiveRecord::Base.connection
      conn.transaction(requires_new: true) { scoped(conn, vars, allow_swap, &block) }
    end

    def self.scoped(conn, vars, allow_swap)
      tenant_guc = PgTenantRls.config.guc
      previous = read(conn, vars.keys)
      guard_swap!(previous[tenant_guc], vars[tenant_guc], tenant_guc) unless allow_swap
      apply(conn, vars)
      begin
        yield
      ensure
        restore(conn, previous)
      end
    end

    # Put the previous values back — unless the transaction has already failed, in which
    # case there is nothing to put back and no way to do it.
    #
    # PostgreSQL refuses every statement on a connection whose transaction is in an error
    # state, so the restore raises InFailedSqlTransaction; raised from an `ensure`, that
    # error replaces the one on its way out, and the caller is told "the transaction is
    # aborted" instead of which constraint aborted it. Reported from a consumer, where a
    # composite foreign key violation arrived as a transaction-state error and the actual
    # cause was invisible.
    #
    # Skipping the restore loses nothing: set_config(..., true) is undone by the rollback
    # of the transaction or subtransaction it ran in, and an aborted transaction has no
    # ending other than a rollback. The check is on the state rather than on whether an
    # exception is in flight, because those are different questions — a block may unwind
    # for reasons that leave the transaction perfectly usable, and it may also complete
    # normally while an outer rescue is still holding an exception.
    def self.restore(conn, previous)
      return if transaction_failed?(conn)

      apply(conn, previous)
    end

    def self.transaction_failed?(conn)
      raw = conn.raw_connection
      raw.respond_to?(:transaction_status) && raw.transaction_status == PG_TRANSACTION_IN_ERROR
    rescue StandardError
      false
    end

    def self.read(conn, guc_names)
      return {} if guc_names.empty?

      selects = guc_names.each_index.map { |i| "current_setting($#{i + 1}, true) AS v#{i}" }.join(", ")
      binds = guc_names.map { |name| bind(name) }
      row = conn.select_one("SELECT #{selects}", "pg_tenant_rls.read", binds)
      guc_names.each_with_index.to_h { |name, i| [name, row["v#{i}"].to_s.empty? ? nil : row["v#{i}"]] }
    end

    def self.apply(conn, vars)
      return if vars.empty?

      selects = vars.keys.each_index.map { |i| "set_config($#{(2 * i) + 1}, $#{(2 * i) + 2}, true)" }.join(", ")
      binds = vars.flat_map { |guc, value| [bind(guc), bind(value&.to_s)] }
      conn.exec_query("SELECT #{selects}", "pg_tenant_rls.apply", binds)
    end

    # Allow entering from untenanted (previous nil) and no-op (same tenant); forbid only
    # tenant -> different-tenant, the single path to a cross-tenant leak.
    def self.guard_swap!(previous, incoming, guc)
      return if incoming.nil? || previous.nil?
      return if previous.to_s == incoming.to_s

      raise SwapError,
            "refusing to swap tenant context #{previous} -> #{incoming} on #{guc}; " \
            "pass allow_swap: true if intentional"
    end

    def self.bind(value)
      ActiveRecord::Relation::QueryAttribute.new(nil, value, ActiveRecord::Type::String.new)
    end

    private_class_method :scoped, :read, :apply, :restore, :transaction_failed?, :guard_swap!, :bind
  end
end
