//! Order statistics over microsecond samples. Nearest-rank percentiles: no interpolation, so
//! every reported value is an actually observed sample.

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Summary {
    pub count: usize,
    pub min_us: i64,
    /// Lower median for an even count, so it is an observed value like the others.
    pub median_us: i64,
    pub p95_us: i64,
    pub max_us: i64,
}

/// Nearest-rank percentile (`ceil(p/100 * n)`-th smallest value) of an already sorted slice.
fn nearest_rank(sorted: &[i64], percentile: u32) -> Option<i64> {
    if sorted.is_empty() || percentile == 0 || percentile > 100 {
        return None;
    }
    let n = sorted.len();
    let rank = (n * percentile as usize).div_ceil(100);
    sorted.get(rank.max(1) - 1).copied()
}

pub fn summarize(values: &[i64]) -> Option<Summary> {
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    Some(Summary {
        count: sorted.len(),
        min_us: *sorted.first()?,
        median_us: nearest_rank(&sorted, 50)?,
        p95_us: nearest_rank(&sorted, 95)?,
        max_us: *sorted.last()?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_has_no_summary() {
        assert_eq!(summarize(&[]), None);
    }

    #[test]
    fn single_sample_is_every_statistic() {
        assert_eq!(
            summarize(&[7]),
            Some(Summary {
                count: 1,
                min_us: 7,
                median_us: 7,
                p95_us: 7,
                max_us: 7
            })
        );
    }

    #[test]
    fn nearest_rank_matches_hand_computed_values() {
        // 1..=20 shuffled: median rank 10 → 10, p95 rank 19 → 19.
        let values: Vec<i64> = vec![
            20, 3, 17, 1, 9, 12, 5, 18, 2, 14, 7, 16, 11, 4, 19, 6, 13, 8, 15, 10,
        ];
        assert_eq!(
            summarize(&values),
            Some(Summary {
                count: 20,
                min_us: 1,
                median_us: 10,
                p95_us: 19,
                max_us: 20
            })
        );
        // n = 21: p95 rank ceil(19.95) = 20.
        let values: Vec<i64> = (1..=21).collect();
        assert_eq!(summarize(&values).map(|s| s.p95_us), Some(20));
    }

    #[test]
    fn negative_values_are_preserved() {
        // T1 can be negative when discovery observes the device before the OS notification.
        let summary = summarize(&[-300, 100, 50]);
        assert_eq!(summary.map(|s| (s.min_us, s.max_us)), Some((-300, 100)));
    }

    #[test]
    fn percentile_bounds_are_rejected() {
        assert_eq!(nearest_rank(&[1, 2], 0), None);
        assert_eq!(nearest_rank(&[1, 2], 101), None);
        assert_eq!(nearest_rank(&[1, 2], 100), Some(2));
    }
}
