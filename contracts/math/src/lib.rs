//! Arithmetic a price needs and `u128` can't hold: the product of two amounts is 256 bits wide.
//! Everything rounds down, and overflow is an answer, not a wrapped number.
#![no_std]

/// `a * b` as its high and low 128 bits.
pub const fn mul_wide(a: u128, b: u128) -> (u128, u128) {
    const LOW: u128 = u64::MAX as u128;
    let (a_high, a_low) = (a >> 64, a & LOW);
    let (b_high, b_low) = (b >> 64, b & LOW);
    let low_low = a_low * b_low;
    let high_low = a_high * b_low;
    let low_high = a_low * b_high;
    let high_high = a_high * b_high;
    let middle = (low_low >> 64) + (high_low & LOW) + (low_high & LOW);
    let low = (low_low & LOW) | (middle << 64);
    let high = high_high + (high_low >> 64) + (low_high >> 64) + (middle >> 64);
    (high, low)
}

/// `a * b / divisor`, rounded down, or None if the divisor is zero or the result doesn't fit.
pub const fn mul_div(a: u128, b: u128, divisor: u128) -> Option<u128> {
    if divisor == 0 {
        return None;
    }
    let (high, low) = mul_wide(a, b);
    if high == 0 {
        return Some(low / divisor);
    }
    if high >= divisor {
        return None;
    }
    // long division, a bit at a time: the remainder stays below the divisor, so at most one bit
    // falls off the top of the shift, and that one means the divisor goes in
    let (mut remainder, mut quotient) = (high, 0u128);
    let mut bit = 128;
    while bit > 0 {
        bit -= 1;
        let carried = remainder >> 127 == 1;
        remainder = (remainder << 1) | ((low >> bit) & 1);
        quotient <<= 1;
        if carried || remainder >= divisor {
            remainder = remainder.wrapping_sub(divisor);
            quotient |= 1;
        }
    }
    Some(quotient)
}

/// The square root of `a * b`, rounded down.
pub fn sqrt_product(a: u128, b: u128) -> u128 {
    if a == 0 || b == 0 {
        return 0;
    }
    let (high, low) = mul_wide(a, b);
    if high == 0 {
        return low.isqrt();
    }
    // Newton from above: `a * b < 2^(bits a + bits b)`, so this start is above the root
    let half = (bits(a) + bits(b)).div_ceil(2);
    let mut x = if half >= 128 { u128::MAX } else { 1 << half };
    loop {
        let Some(quotient) = mul_div(a, b, x) else {
            return x;
        };
        let next = (x >> 1) + (quotient >> 1) + (x & quotient & 1);
        if next >= x {
            return x;
        }
        x = next;
    }
}

const fn bits(value: u128) -> u32 {
    128 - value.leading_zeros()
}

/// Whether `a * b >= c * d`.
pub const fn product_at_least(a: u128, b: u128, c: u128, d: u128) -> bool {
    let (left_high, left_low) = mul_wide(a, b);
    let (right_high, right_low) = mul_wide(c, d);
    left_high > right_high || (left_high == right_high && left_low >= right_low)
}

#[cfg(test)]
mod tests {
    use super::*;

    const EDGES: [u128; 12] = [
        0,
        1,
        2,
        3,
        1 << 64,
        (1 << 64) + 1,
        (1 << 112) - 1,
        1 << 112,
        1 << 127,
        (1 << 127) + 1,
        u128::MAX - 1,
        u128::MAX,
    ];

    /// A small generator, so a failure is the same failure every run.
    fn numbers(count: usize) -> impl Iterator<Item = u128> {
        let mut state = 0x9E37_79B9_7F4A_7C15u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        (0..count).map(move |_| {
            let wide = (u128::from(next()) << 64) | u128::from(next());
            wide >> (next() % 128)
        })
    }

    fn pairs() -> impl Iterator<Item = (u128, u128)> {
        let random = numbers(4_000);
        let edges = EDGES
            .iter()
            .flat_map(|&a| EDGES.iter().map(move |&b| (a, b)));
        let mut last = 1;
        edges.chain(random.map(move |n| {
            let pair = (last, n);
            last = n;
            pair
        }))
    }

    /// 256-bit addition, to check results without trusting the division.
    fn add_wide((high, low): (u128, u128), value: u128) -> (u128, u128) {
        let (low, carry) = low.overflowing_add(value);
        (high.wrapping_add(u128::from(carry)), low)
    }

    #[test]
    fn mul_wide_matches_u128_when_it_fits_and_known_values_when_not() {
        assert_eq!(mul_wide(6, 7), (0, 42));
        assert_eq!(mul_wide(u128::MAX, 1), (0, u128::MAX));
        assert_eq!(mul_wide(1 << 64, 1 << 64), (1, 0));
        assert_eq!(mul_wide(u128::MAX, u128::MAX), (u128::MAX - 1, 1));
        for (a, b) in pairs() {
            if let Some(product) = a.checked_mul(b) {
                assert_eq!(mul_wide(a, b), (0, product));
            }
            assert_eq!(mul_wide(a, b), mul_wide(b, a));
        }
    }

    #[test]
    fn mul_div_is_exact_and_rounds_down() {
        for (a, b) in pairs() {
            for divisor in [
                1,
                3,
                10_000,
                a | 1,
                b | 1,
                (a >> 1) | 1,
                (a ^ b) | 1,
                u128::MAX,
            ] {
                let product = mul_wide(a, b);
                let Some(quotient) = mul_div(a, b, divisor) else {
                    let (high, _) = product;
                    assert!(high >= divisor, "None only when it can't fit");
                    continue;
                };
                // quotient * divisor <= product < (quotient + 1) * divisor
                let below = mul_wide(quotient, divisor);
                assert!(below <= product, "{a} * {b} / {divisor} rounded up");
                let remainder = product.1.wrapping_sub(below.1);
                assert_eq!(add_wide(below, remainder), product);
                assert!(
                    remainder < divisor,
                    "{a} * {b} / {divisor} rounded too far down"
                );
            }
        }
    }

    #[test]
    fn mul_div_refuses_what_does_not_fit() {
        assert_eq!(mul_div(5, 5, 0), None);
        assert_eq!(mul_div(u128::MAX, u128::MAX, 1), None);
        assert_eq!(mul_div(u128::MAX, 2, 1), None);
        assert_eq!(mul_div(u128::MAX, 2, 2), Some(u128::MAX));
        assert_eq!(mul_div(u128::MAX, u128::MAX, u128::MAX), Some(u128::MAX));
    }

    #[test]
    fn sqrt_product_is_the_largest_root() {
        assert_eq!(sqrt_product(0, 5), 0);
        assert_eq!(sqrt_product(4, 9), 6);
        assert_eq!(sqrt_product(1 << 112, 1 << 112), 1 << 112);
        assert_eq!(sqrt_product(u128::MAX, u128::MAX), u128::MAX);
        for (a, b) in pairs() {
            let root = sqrt_product(a, b);
            let product = mul_wide(a, b);
            assert!(
                mul_wide(root, root) <= product,
                "root of {a} * {b} too high"
            );
            if root < u128::MAX {
                assert!(
                    mul_wide(root + 1, root + 1) > product,
                    "root of {a} * {b} too low"
                );
            }
        }
    }

    #[test]
    fn products_compare_past_128_bits() {
        assert!(product_at_least(
            u128::MAX,
            u128::MAX,
            u128::MAX,
            u128::MAX - 1
        ));
        assert!(!product_at_least(
            u128::MAX,
            u128::MAX - 1,
            u128::MAX,
            u128::MAX
        ));
        assert!(product_at_least(1 << 100, 1 << 100, 1 << 99, 1 << 101));
    }
}
