# frozen_string_literal: true

module PgTenantRls
  # One policy within an archetype: which command it governs, whether it widens or narrows
  # access, and the expressions deciding which rows it reaches.
  #
  # The expressions are opaque. A host writing `id IN (SELECT its_own_function())` gets that
  # text written verbatim — the gem neither parses nor validates it, which is what lets an
  # archetype belong to a host without the gem learning anything about that host.
  class PolicyDeclaration
    # Which clause each command accepts. Not a convention of this gem — PostgreSQL's rule, so
    # a declaration breaking it can only ever produce a statement the database rejects.
    CLAUSES = {
      "SELECT" => { using: true, check: false },
      "INSERT" => { using: false, check: true },
      "UPDATE" => { using: true, check: true },
      "DELETE" => { using: true, check: false },
      "ALL" => { using: true, check: true }
    }.freeze

    # The clauses a declaration may carry. Collected as one argument rather than as two
    # keywords so that a declaration stays inside the parameter budget — and because they
    # are one thing: the predicate, which is also how create_policy! has always taken them.
    CLAUSE_NAMES = %i[using check].freeze

    attr_reader :suffix, :name, :command, :using, :check

    def initialize(suffix: nil, name: nil, command: "ALL", permissive: true, **predicate)
      @suffix = suffix
      @name = name
      @command = command.to_s.upcase
      @permissive = permissive
      @using = predicate[:using]
      @check = predicate[:check]
      validate!(predicate.keys)
    end

    def permissive? = @permissive

    # The policy's name on a given table. An explicit name wins, so an archetype can adopt
    # policies a schema already carries instead of forcing a rename of live objects.
    def policy_name(table)
      name || "#{table}_#{suffix}"
    end

    def ==(other)
      other.is_a?(self.class) && to_h == other.to_h
    end
    alias eql? ==

    def hash = to_h.hash

    def to_h
      { suffix: suffix, name: name, command: command, permissive: @permissive,
        using: using, check: check }
    end

    private

    def validate!(given)
      raise PgTenantRls::Error, "a policy needs a suffix or an explicit name" if suffix.nil? && name.nil?

      reject_unknown_clause(given)
      reject_unusable_clause(CLAUSES.fetch(command) { raise PgTenantRls::Error, unknown_command })
      reject_empty_predicate
    end

    def unknown_command
      "unknown command #{command.inspect}; expected one of #{CLAUSES.keys.join(", ")}"
    end

    # A keyword collected into the predicate but not part of it is a typo, and a typo that
    # is quietly dropped writes a policy against something other than what was declared.
    def reject_unknown_clause(given)
      unknown = given - CLAUSE_NAMES
      return if unknown.empty?

      raise PgTenantRls::Error,
            "a policy takes #{CLAUSE_NAMES.map { |c| "#{c}:" }.join(" and ")}, " \
            "not #{unknown.map(&:inspect).join(", ")}"
    end

    def reject_unusable_clause(allowed)
      raise PgTenantRls::Error, "#{command} takes no USING expression" if using && !allowed[:using]
      raise PgTenantRls::Error, "#{command} takes no WITH CHECK expression" if check && !allowed[:check]
    end

    def reject_empty_predicate
      return unless using.nil? && check.nil?

      raise PgTenantRls::Error, "#{command} needs a USING or WITH CHECK expression"
    end
  end
end
