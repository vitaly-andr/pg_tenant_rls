# frozen_string_literal: true

module PgTenantRls
  module Inspector
    # What an audit found, and what it looked at.
    #
    # The second half is the point. A bare list of problems answers "was anything wrong" and
    # cannot answer "was anything examined", so an audit that silently degraded to checking
    # nothing returned exactly what a clean perimeter returns — and went on doing so, because
    # the only wrong outcome of such a check is a reassuring one.
    #
    # Carrying both makes that state impossible to express as success: no problems over
    # nothing examined is a different value from no problems over twenty tables, a role and a
    # perimeter, and verify! refuses the first.
    #
    # `skipped` is not a failure. A perimeter sweep needs prefixes and a membership check
    # needs a role; a consumer that supplies neither has opted out of those two questions and
    # is entitled to. What it is not entitled to is not knowing.
    Report = Struct.new(:problems, :checked, :skipped, keyword_init: true) do
      def clean? = problems.empty?

      def nothing_checked? = checked.empty?

      def to_s
        [section("problems", problems), section("checked", checked),
         section("not checked", skipped)].compact.join("\n")
      end

      private

      def section(title, entries)
        return nil if entries.empty?

        "#{title}:\n" + entries.map { |entry| "  #{entry}" }.join("\n")
      end
    end
  end
end
