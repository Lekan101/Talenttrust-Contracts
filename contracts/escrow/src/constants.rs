/// Minimum valid reputation rating (inclusive).
///
/// # Invariant
/// `MIN_RATING >= 1` — zero is not a valid rating because absence of rating
/// is represented by `None`, not by a zero value.  Every reputation-issuing
/// path (`issue_reputation`) must reject `rating < MIN_RATING`.
pub const MIN_RATING: u32 = 1;

/// Maximum valid reputation rating (inclusive).
///
/// # Invariant
/// `MAX_RATING >= MIN_RATING` — the valid rating interval must be non-empty.
/// The current 1–5 scale matches common freelance platforms and is small
/// enough to avoid precision disputes.  `issue_reputation` must reject
/// `rating > MAX_RATING`.
pub const MAX_RATING: u32 = 5;

/// Max byte length of a reputation feedback comment.
///
/// # Invariant
/// `MAX_COMMENT_BYTES >= 1` — a zero-length comment is rejected as empty; use
/// a minimum of 1 byte so the interval `[1, MAX_COMMENT_BYTES]` is non-empty.
/// `issue_reputation` must reject comments whose `len() > MAX_COMMENT_BYTES`.
pub const MAX_COMMENT_BYTES: u32 = 200;

/// Unit increment for pending reputation credits.
///
/// # Invariant
/// `REPUTATION_CREDIT_INCREMENT > 0` — credits must always be positive; a
/// non-positive increment would allow reputation credit balances to stagnate
/// or decrease on successful contract completion, which is logically invalid.
pub const REPUTATION_CREDIT_INCREMENT: i128 = 1;

/// Basis-point scaling factor for `get_average_rating` (×10_000 preserves four decimal places).
///
/// # Invariant
/// `SCALE > 0` — the scaling factor must be strictly positive so that the
/// fixed-point arithmetic used in `get_average_rating` never divides by zero
/// and always yields a non-negative result for valid ratings.
pub const SCALE: i128 = 10_000;

/// Upper bound on the `limit` parameter of paginated read views.
///
/// Keeps per-call storage reads bounded and prevents callers from requesting
/// unbounded scans in a single invocation.
///
/// # Invariant
/// `PAGE_CEILING >= 1` — at least one record per page must be returnable;
/// a ceiling of zero would make every paginated read vacuous.
pub const PAGE_CEILING: u32 = 50;

// ── Compile-time invariant assertions ────────────────────────────────────────
//
// These assertions are evaluated at compile time via `const _` blocks.  A
// violation is a hard compile error, not a runtime panic, which is the
// strongest possible guarantee that the constants satisfy their documented
// relationships regardless of future edits.

/// `MIN_RATING` must be at least 1 — zero is not representable as a valid rating.
const _: () = assert!(MIN_RATING >= 1, "MIN_RATING must be >= 1");

/// `MAX_RATING` must be >= `MIN_RATING` — the valid interval must be non-empty.
const _: () = assert!(
    MAX_RATING >= MIN_RATING,
    "MAX_RATING must be >= MIN_RATING"
);

/// `MAX_COMMENT_BYTES` must be at least 1 — comments cannot be vacuous.
const _: () = assert!(
    MAX_COMMENT_BYTES >= 1,
    "MAX_COMMENT_BYTES must be >= 1"
);

/// `REPUTATION_CREDIT_INCREMENT` must be strictly positive.
const _: () = assert!(
    REPUTATION_CREDIT_INCREMENT > 0,
    "REPUTATION_CREDIT_INCREMENT must be > 0"
);

/// `SCALE` must be strictly positive — used as a fixed-point divisor.
const _: () = assert!(SCALE > 0, "SCALE must be > 0");

/// `PAGE_CEILING` must be at least 1 — every paginated call must be able to
/// return at least one record.
const _: () = assert!(PAGE_CEILING >= 1, "PAGE_CEILING must be >= 1");

#[cfg(test)]
mod tests {
    use super::*;

    // ── Value pinning ────────────────────────────────────────────────────────
    //
    // These tests pin the concrete values of every constant.  They exist so
    // that any future edit to a constant immediately surfaces as a test
    // failure, forcing an explicit decision about downstream impact.

    #[test]
    fn constants_have_expected_values() {
        assert_eq!(MIN_RATING, 1);
        assert_eq!(MAX_RATING, 5);
        assert_eq!(MAX_COMMENT_BYTES, 200);
        assert_eq!(REPUTATION_CREDIT_INCREMENT, 1);
        assert_eq!(SCALE, 10_000);
        assert_eq!(PAGE_CEILING, 50);
    }

    // ── Invariant coverage ───────────────────────────────────────────────────

    #[test]
    fn min_rating_is_at_least_one() {
        assert!(MIN_RATING >= 1, "MIN_RATING must be >= 1");
    }

    #[test]
    fn max_rating_is_at_least_min_rating() {
        assert!(
            MAX_RATING >= MIN_RATING,
            "MAX_RATING ({MAX_RATING}) must be >= MIN_RATING ({MIN_RATING})"
        );
    }

    #[test]
    fn rating_range_is_non_empty() {
        // There must be at least one valid rating value.
        assert!(MAX_RATING >= MIN_RATING);
        let count = MAX_RATING - MIN_RATING + 1;
        assert!(count >= 1, "rating range must contain at least one value");
    }

    #[test]
    fn max_comment_bytes_is_at_least_one() {
        assert!(MAX_COMMENT_BYTES >= 1, "MAX_COMMENT_BYTES must be >= 1");
    }

    #[test]
    fn reputation_credit_increment_is_positive() {
        assert!(
            REPUTATION_CREDIT_INCREMENT > 0,
            "REPUTATION_CREDIT_INCREMENT must be strictly positive"
        );
    }

    #[test]
    fn scale_is_positive() {
        assert!(SCALE > 0, "SCALE must be strictly positive");
    }

    #[test]
    fn page_ceiling_is_at_least_one() {
        assert!(PAGE_CEILING >= 1, "PAGE_CEILING must be >= 1");
    }

    // ── Boundary coverage ────────────────────────────────────────────────────

    #[test]
    fn rating_boundary_values() {
        // Both inclusive endpoints are valid.
        assert!(MIN_RATING >= 1 && MIN_RATING <= MAX_RATING);
        assert!(MAX_RATING >= MIN_RATING);

        // The value just below MIN_RATING must be out-of-range.
        // MIN_RATING is u32, so wrapping_sub avoids underflow.
        let below_min = MIN_RATING.wrapping_sub(1);
        assert!(
            below_min < MIN_RATING || below_min > MAX_RATING,
            "value below MIN_RATING ({below_min}) must be out of [MIN_RATING, MAX_RATING]"
        );

        // The value just above MAX_RATING must be out-of-range.
        let above_max = MAX_RATING + 1;
        assert!(
            above_max > MAX_RATING,
            "value above MAX_RATING ({above_max}) must exceed MAX_RATING"
        );
    }

    #[test]
    fn comment_boundary_values() {
        // Exactly at the limit is valid.
        assert!(MAX_COMMENT_BYTES >= 1);
        // One byte over the limit exceeds the cap.
        let over = MAX_COMMENT_BYTES + 1;
        assert!(over > MAX_COMMENT_BYTES);
    }

    #[test]
    fn page_ceiling_boundary() {
        // Requesting exactly PAGE_CEILING items is at-limit (valid).
        assert!(PAGE_CEILING >= 1);
        // Requesting PAGE_CEILING + 1 exceeds the limit.
        let over = PAGE_CEILING + 1;
        assert!(over > PAGE_CEILING);
    }

    // ── Idempotency: re-checking invariants as runtime assertions ────────────
    //
    // The compile-time `const _` assertions already enforce these, but an
    // explicit runtime test makes the contract visible in `cargo test` output
    // and ensures that `cargo test` and `cargo build` both catch violations.

    #[test]
    fn compile_time_invariants_hold_at_runtime() {
        // Mirror every `const _` assertion as a runtime check.
        assert!(MIN_RATING >= 1);
        assert!(MAX_RATING >= MIN_RATING);
        assert!(MAX_COMMENT_BYTES >= 1);
        assert!(REPUTATION_CREDIT_INCREMENT > 0);
        assert!(SCALE > 0);
        assert!(PAGE_CEILING >= 1);
    }
}
