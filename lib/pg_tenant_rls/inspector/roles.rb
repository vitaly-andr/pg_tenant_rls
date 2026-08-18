# frozen_string_literal: true

module PgTenantRls
  module Inspector
    # Questions about the ROLE rather than about a table: whether policies bind to it at all,
    # and whether it can step out from under them on request.
    #
    # Split from Inspector along the seam that appeared when the second question arrived. The
    # two are close enough to be confused and must not be merged: one asks what is true now,
    # the other what is reachable. A single verdict combining them would call a correctly
    # isolated session unenforced — and would do so in the first line of an isolation suite,
    # the worst possible place for a false alarm.
    module Roles
      # Roles carrying SUPERUSER or BYPASSRLS that this role can become, and therefore the
      # policies it can step out from under whenever it likes.
      #
      # Role attributes are NOT inherited through membership — measured: a member of a
      # BYPASSRLS role reads its rows under the policy, exactly as an unrelated role would.
      # What membership grants is SET ROLE, which needs no password and takes one statement,
      # and RLS then consults the attributes of the role in effect. So this is not a hole that
      # is open; it is a hole that opens on request — the same thing to an auditor, and a
      # different thing to a reader of pg_roles.
      #
      # pg_has_role(..., 'MEMBER') rather than a join on pg_auth_members, because membership
      # is transitive for SET ROLE and a direct-membership query misses a chain entirely —
      # measured on a → b → c, where a reaches c while pg_auth_members shows a nothing at all.
      # 'MEMBER' rather than 'USAGE': USAGE respects NOINHERIT and SET ROLE does not, and it
      # is SET ROLE that escalates.
      #
      # The role is resolved to an oid in a subquery: pg_has_role raises on a name that does
      # not exist, and "the role is not there yet" is an ordinary state during provisioning.
      def privileged_memberships(connection, role)
        return [] if role.nil?

        quoted = connection.quote(role.to_s)
        connection.select_values(
          "SELECT rolname FROM pg_roles WHERE (rolsuper OR rolbypassrls) AND rolname <> #{quoted} " \
          "AND pg_has_role((SELECT oid FROM pg_roles WHERE rolname = #{quoted}), oid, 'MEMBER') " \
          "ORDER BY rolname"
        )
      end

      # Reported by audit rather than raised at provisioning time. Refusing to provision would
      # turn a latent hole into an outage at the worst possible moment, and would not close it
      # either — an administrator who needs the group will remove the check, not the group.
      # Reported here it travels with the deploy check, which is where it stays current: a
      # membership added six months after setup is invisible to anything that ran once.
      def membership_problems(connection, role)
        privileged_memberships(connection, role).map do |privileged|
          "#{role}: may SET ROLE #{privileged}, which bypasses every policy — no password needed"
        end
      end

      # Whether the CURRENT role can be held by policies at all. Under a superuser or a
      # BYPASSRLS role every policy is inert, so an isolation test run as that role passes
      # for the wrong reason — the most expensive false green there is. Worth asserting as
      # the very first line of an isolation suite.
      #
      # Scope: this answers what is true of the role in effect (rolsuper, rolbypassrls) and
      # deliberately says nothing about what it could become — that is privileged_memberships
      # above. The other way to escape policies is per-table: an owner reading its own table
      # without FORCE ROW LEVEL SECURITY, which is not a property of the role and is reported
      # per table by #call as rls_forced. The three together cover the ways enforcement is off.
      def enforced_for_current_role?(connection)
        row = connection.select_one("SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user")
        return false if row.nil?

        !(Catalog.cast_bool(row["rolsuper"]) || Catalog.cast_bool(row["rolbypassrls"]))
      end
    end
  end
end
