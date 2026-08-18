# frozen_string_literal: true

module PgTenantRls
  module Inspector
    # One question the audit asked, or declined to ask.
    #
    # `key` (:table, :perimeter, :role) exists because a consumer asserting its own coverage —
    # "exactly one question was skipped, and it was the role one" — must not have to match on
    # English. A message is written for a person and has to stay free to improve; a spec
    # pinned to its first word turns every rewording into a breakage, and the consumer ends up
    # asserting on the shape of a sentence rather than on the fact it describes.
    #
    # Same reasoning as the Report below, one level down: a value a caller decides on is never
    # prose. Reported by a consumer who had to write start_with("role:") an hour after the
    # Report shipped.
    Entry = Struct.new(:key, :subject, :message, keyword_init: true) do
      def to_s = message
    end

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
    #
    # `problems` stay plain strings: their content varies with what was wrong, and the
    # decision a caller makes on them is "is this empty" — no reading required.
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

        "#{title}:\n#{entries.map { |entry| "  #{entry}" }.join("\n")}"
      end
    end
  end
end
