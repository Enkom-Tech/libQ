//! Welch t-test with percentile cropping (dudect style).

pub fn welch_t(a: &[f64], b: &[f64]) -> Option<f64> {
    let (na, nb) = (a.len() as f64, b.len() as f64);
    if a.len() < 2 || b.len() < 2 {
        return None;
    }
    let ma = a.iter().sum::<f64>() / na;
    let mb = b.iter().sum::<f64>() / nb;
    let va = a.iter().map(|x| (x - ma).powi(2)).sum::<f64>() / (na - 1.0);
    let vb = b.iter().map(|x| (x - mb).powi(2)).sum::<f64>() / (nb - 1.0);
    let se = (va / na + vb / nb).sqrt();
    if se == 0.0 || !se.is_finite() {
        // Identical constant samples: no measurable difference (or a degenerate clock).
        return if (ma - mb).abs() == 0.0 {
            Some(0.0)
        } else {
            None
        };
    }
    Some((ma - mb) / se)
}

pub const CROPS: [f64; 6] = [1.0, 0.99, 0.95, 0.90, 0.75, 0.50];

/// Largest |t| over the crops; returns `(max_abs_t, crop)`. `None` when a class is too small.
pub fn max_cropped_t(c0: &[f64], c1: &[f64]) -> Option<(f64, f64)> {
    if c0.len() < 100 || c1.len() < 100 {
        return None;
    }
    let mut pooled: Vec<f64> = c0.iter().chain(c1).copied().collect();
    pooled.sort_by(|a, b| a.total_cmp(b));
    let mut best: Option<(f64, f64)> = None;
    for &p in &CROPS {
        let idx = ((p * pooled.len() as f64).ceil() as usize).clamp(1, pooled.len()) - 1;
        let cut = pooled[idx];
        let a: Vec<f64> = c0.iter().copied().filter(|x| *x <= cut).collect();
        let b: Vec<f64> = c1.iter().copied().filter(|x| *x <= cut).collect();
        if let Some(t) = welch_t(&a, &b)
            && best.is_none_or(|(bt, _)| t.abs() > bt)
        {
            best = Some((t.abs(), p));
        }
    }
    best
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn detects_shift_and_ignores_identical() {
        let a: Vec<f64> = (0..1000).map(|i| 100.0 + (i % 7) as f64).collect();
        let b: Vec<f64> = (0..1000).map(|i| 110.0 + (i % 7) as f64).collect();
        assert!(max_cropped_t(&a, &b).unwrap().0 > 50.0);
        assert!(max_cropped_t(&a, &a).unwrap().0 < 1e-9);
    }
    #[test]
    fn too_few_samples_is_none() {
        assert!(max_cropped_t(&[1.0; 10], &[2.0; 10]).is_none());
    }
}
