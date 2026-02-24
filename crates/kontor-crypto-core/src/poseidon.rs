//! Poseidon hash for Pallas scalar field, arity 2, Strength::Standard.
//! Compatible with nova-snark's Sponge API (same constants and permutation).
//! Uses halo2curves::pasta::Fq so constants match Nova (same as kontor-crypto FieldElement).

#[cfg(not(feature = "nova_poseidon"))]
use ff::{Field, PrimeField};
use halo2curves::pasta::Fq;

/// Pallas scalar (same type as Nova uses for PallasEngine::Scalar).
pub type FieldElement = Fq;

#[cfg(not(feature = "nova_poseidon"))]
mod standalone_poseidon {
    use super::*;
    use std::ops::AddAssign;

    // --- Matrix helpers (minimal port from nova-snark for constant generation) ---

    type Matrix<F> = Vec<Vec<F>>;

    fn rows<T>(matrix: &Matrix<T>) -> usize {
        matrix.len()
    }

    fn columns<T>(matrix: &Matrix<T>) -> usize {
        if matrix.is_empty() {
            0
        } else {
            let n = matrix[0].len();
            for row in matrix {
                assert_eq!(row.len(), n, "not a matrix");
            }
            n
        }
    }

    fn is_square<T>(matrix: &Matrix<T>) -> bool {
        rows(matrix) == columns(matrix)
    }

    fn vec_add<F: PrimeField>(a: &[F], b: &[F]) -> Vec<F> {
        a.iter()
            .zip(b.iter())
            .map(|(a, b)| {
                let mut r = *a;
                r.add_assign(b);
                r
            })
            .collect()
    }

    fn vec_sub<F: PrimeField>(a: &[F], b: &[F]) -> Vec<F> {
        a.iter()
            .zip(b.iter())
            .map(|(a, b)| {
                let mut r = *a;
                r.sub_assign(b);
                r
            })
            .collect()
    }

    fn scalar_vec_mul<F: PrimeField>(scalar: F, vec: &[F]) -> Vec<F> {
        vec.iter()
            .map(|v| {
                let mut t = scalar;
                t.mul_assign(v);
                t
            })
            .collect()
    }

    fn transpose<F: PrimeField>(matrix: &Matrix<F>) -> Matrix<F> {
        let r = rows(matrix);
        let c = columns(matrix);
        (0..c)
            .map(|j| (0..r).map(|i| matrix[i][j]).collect())
            .collect()
    }

    fn left_apply_matrix<F: PrimeField>(m: &Matrix<F>, v: &[F]) -> Vec<F> {
        assert!(is_square(m));
        assert_eq!(rows(m), v.len());
        let mut result = vec![F::ZERO; v.len()];
        for (res, row) in result.iter_mut().zip(m.iter()) {
            for (mij, vj) in row.iter().zip(v.iter()) {
                let mut t = *mij;
                t.mul_assign(vj);
                res.add_assign(&t);
            }
        }
        result
    }

    fn minor<F: PrimeField>(matrix: &Matrix<F>, skip_i: usize, skip_j: usize) -> Matrix<F> {
        matrix
            .iter()
            .enumerate()
            .filter_map(|(i, row)| {
                if i == skip_i {
                    None
                } else {
                    let mut new_row = row.clone();
                    new_row.remove(skip_j);
                    Some(new_row)
                }
            })
            .collect()
    }

    fn make_identity<F: PrimeField>(size: usize) -> Matrix<F> {
        let mut m = vec![vec![F::ZERO; size]; size];
        for (i, row) in m.iter_mut().enumerate() {
            row[i] = F::ONE;
        }
        m
    }

    fn eliminate<F: PrimeField>(
        matrix: &Matrix<F>,
        column: usize,
        shadow: &mut Matrix<F>,
    ) -> Option<Matrix<F>> {
        let zero = F::ZERO;
        let pivot_index = (0..rows(matrix))
            .find(|&i| matrix[i][column] != zero && (0..column).all(|j| matrix[i][j] == zero))?;
        let pivot = matrix[pivot_index].clone();
        let pivot_val = pivot[column];
        let inv_pivot = match pivot_val.invert().into() {
            Some(x) => x,
            None => return None,
        };
        let mut result = vec![pivot.clone()];
        for (i, row) in matrix.iter().enumerate() {
            if i == pivot_index {
                continue;
            }
            let val = row[column];
            if val == zero {
                result.push(row.clone());
            } else {
                let mut factor = val;
                factor.mul_assign(&inv_pivot);
                let scaled = scalar_vec_mul(factor, &pivot);
                result.push(vec_sub(row, &scaled));
                let sp = &shadow[pivot_index];
                let scaled_shadow = scalar_vec_mul(factor, sp);
                let sr = &shadow[i];
                shadow[i] = vec_sub(sr, &scaled_shadow);
            }
        }
        let pivot_row = shadow.remove(pivot_index);
        shadow.insert(0, pivot_row);
        Some(result)
    }

    fn upper_triangular<F: PrimeField>(
        matrix: &Matrix<F>,
        shadow: &mut Matrix<F>,
    ) -> Option<Matrix<F>> {
        assert!(is_square(matrix));
        let mut result = Vec::new();
        let mut shadow_result = Vec::new();
        let mut curr = matrix.clone();
        let mut sh = shadow.clone();
        let mut column = 0;
        while curr.len() > 1 {
            curr = eliminate(&curr, column, &mut sh)?;
            result.push(curr[0].clone());
            shadow_result.push(sh[0].clone());
            column += 1;
            curr = curr[1..].to_vec();
            sh = sh[1..].to_vec();
        }
        result.push(curr[0].clone());
        shadow_result.push(sh[0].clone());
        *shadow = shadow_result;
        Some(result)
    }

    fn reduce_to_identity<F: PrimeField>(matrix: &Matrix<F>, shadow: &mut Matrix<F>) -> Option<()> {
        let size = rows(matrix);
        let mut result: Vec<Vec<F>> = Vec::new();
        let mut shadow_result: Vec<Vec<F>> = Vec::new();
        for i in 0..size {
            let idx = size - i - 1;
            let row = &matrix[idx];
            let shadow_row = &shadow[idx];
            let val = row[idx];
            let inv = match val.invert().into() {
                Some(x) => x,
                None => return None,
            };
            let mut normalized = scalar_vec_mul(inv, row);
            let mut shadow_normalized = scalar_vec_mul(inv, shadow_row);
            for j in 0..i {
                let idx2 = size - j - 1;
                let v = normalized[idx2];
                let sub = scalar_vec_mul(v, &result[j]);
                let shadow_sub = scalar_vec_mul(v, &shadow_result[j]);
                normalized = vec_sub(&normalized, &sub);
                shadow_normalized = vec_sub(&shadow_normalized, &shadow_sub);
            }
            result.push(normalized);
            shadow_result.push(shadow_normalized);
        }
        result.reverse();
        shadow_result.reverse();
        *shadow = shadow_result;
        Some(())
    }

    fn invert<F: PrimeField>(matrix: &Matrix<F>) -> Option<Matrix<F>> {
        let mut shadow = make_identity(columns(matrix));
        let ut = upper_triangular(matrix, &mut shadow);
        ut.and_then(|u| reduce_to_identity(&u, &mut shadow).map(|_| shadow))
    }

    // --- Round numbers (Poseidon paper, 128-bit security) ---

    const PRIME_BITLEN: usize = 256;
    const M: usize = 128;

    fn n_sboxes(t: usize, rf: usize, rp: usize) -> usize {
        t * rf + rp
    }

    fn round_numbers_secure(t: usize, rf: usize, rp: usize) -> bool {
        let (rp_f, t_f, n_f, m_f) = (rp as f32, t as f32, PRIME_BITLEN as f32, M as f32);
        let rf_stat = if m_f <= (n_f - 3.0) * (t_f + 1.0) {
            6.0
        } else {
            10.0
        };
        let rf_interp = 0.43 * m_f + t_f.log2() - rp_f;
        let rf_grob_1 = 0.21 * n_f - rp_f;
        let rf_grob_2 = (0.14 * n_f - 1.0 - rp_f) / (t_f - 1.0);
        let rf_max = [rf_stat, rf_interp, rf_grob_1, rf_grob_2]
            .iter()
            .map(|x| x.ceil() as usize)
            .max()
            .unwrap();
        rf >= rf_max
    }

    pub(super) fn round_numbers_base(arity: usize) -> (usize, usize) {
        let t = arity + 1;
        let mut rf = 0usize;
        let mut rp = 0usize;
        let mut n_min = usize::MAX;
        for mut rf_test in (2..=1000).step_by(2) {
            for mut rp_test in 4..200 {
                if round_numbers_secure(t, rf_test, rp_test) {
                    rf_test += 2;
                    rp_test = (1.075 * rp_test as f32).ceil() as usize;
                    let n = n_sboxes(t, rf_test, rp_test);
                    if n < n_min || (n == n_min && rf_test < rf) {
                        rf = rf_test;
                        rp = rp_test;
                        n_min = n;
                    }
                }
            }
        }
        (rf, rp)
    }

    // --- Grain LFSR round constants ---

    fn append_bits(vec: &mut Vec<bool>, n: usize, val: u128) {
        for i in (0..n).rev() {
            vec.push((val >> i) & 1 != 0);
        }
    }

    struct Grain {
        state: Vec<bool>,
        field_size: u16,
    }

    impl Grain {
        fn new(init: Vec<bool>, field_size: u16) -> Self {
            assert_eq!(init.len(), 80);
            let mut g = Grain {
                state: init,
                field_size,
            };
            for _ in 0..160 {
                g.next_bit();
            }
            g
        }
        fn bit(&self, i: usize) -> bool {
            self.state[i]
        }
        fn next_bit(&mut self) -> bool {
            let new_bit = self.bit(62)
                ^ self.bit(51)
                ^ self.bit(38)
                ^ self.bit(23)
                ^ self.bit(13)
                ^ self.bit(0);
            self.state.remove(0);
            self.state.push(new_bit);
            new_bit
        }
        /// Build a byte from the next `bits` bits, MSB first.
        /// Uses Iterator (self.next()) = self-shrinking output to match Nova's take(bit_count).
        fn next_byte(&mut self, bits: usize) -> u8 {
            let mut acc = 0u8;
            for _ in 0..bits {
                acc <<= 1;
                if self.next().unwrap() {
                    acc += 1;
                }
            }
            acc
        }
        fn get_next_bytes(&mut self, out: &mut [u8]) {
            let rem = self.field_size as usize % 8;
            if rem > 0 {
                out[0] = self.next_byte(rem);
            } else {
                out[0] = self.next_byte(8);
            }
            for b in out.iter_mut().skip(1) {
                *b = self.next_byte(8);
            }
        }
    }

    impl Iterator for Grain {
        type Item = bool;
        fn next(&mut self) -> Option<bool> {
            while !self.next_bit() {
                self.next_bit();
            }
            Some(self.next_bit())
        }
    }

    const SBOX: u8 = 1;
    const FIELD: u8 = 1;

    /// Generate round constants with explicit round numbers (for Nova compatibility).
    fn round_constants_for_params<F: PrimeField>(
        arity: usize,
        full_rounds: usize,
        partial_rounds: usize,
    ) -> Vec<F> {
        let t = (arity + 1) as u16;
        let r_f = full_rounds as u16;
        let r_p = partial_rounds as u16;
        let field_size = F::NUM_BITS.min(u32::from(u16::MAX)) as u16;
        let n_bytes = F::Repr::default().as_ref().len();
        assert_eq!(n_bytes, 32, "only 32-byte fields supported");
        let num_constants = (full_rounds + partial_rounds) * (arity + 1);
        let mut init = Vec::new();
        append_bits(&mut init, 2, u128::from(FIELD));
        append_bits(&mut init, 4, u128::from(SBOX));
        append_bits(&mut init, 12, u128::from(field_size));
        append_bits(&mut init, 12, u128::from(t));
        append_bits(&mut init, 10, u128::from(r_f));
        append_bits(&mut init, 10, u128::from(r_p));
        append_bits(&mut init, 30, 0x3FFF_FFFF);
        let mut grain = Grain::new(init, field_size);
        let mut out = Vec::with_capacity(num_constants);
        for _ in 0..num_constants {
            loop {
                let mut repr = F::Repr::default();
                grain.get_next_bytes(repr.as_mut());
                repr.as_mut().reverse();
                if let Some(f) = F::from_repr_vartime(repr) {
                    out.push(f);
                    break;
                }
            }
        }
        out
    }

    // --- MDS ---

    fn generate_mds<F: PrimeField>(t: usize) -> Matrix<F> {
        let xs: Vec<F> = (0..t as u64).map(F::from).collect();
        let ys: Vec<F> = (t as u64..2 * t as u64).map(F::from).collect();
        let matrix: Matrix<F> = xs
            .iter()
            .map(|xi| {
                ys.iter()
                    .map(|yj| {
                        let mut tmp = *xi;
                        tmp.add_assign(yj);
                        tmp.invert().unwrap()
                    })
                    .collect()
            })
            .collect();
        assert_eq!(matrix, transpose(&matrix), "MDS must be symmetric");
        matrix
    }

    #[derive(Clone)]
    struct MdsMatrices<F: PrimeField> {
        m: Matrix<F>,
        m_inv: Matrix<F>,
        _m_hat: Matrix<F>,
        _m_hat_inv: Matrix<F>,
        m_prime: Matrix<F>,
        m_double_prime: Matrix<F>,
    }

    fn make_prime<F: PrimeField>(m: &Matrix<F>) -> Matrix<F> {
        m.iter()
            .enumerate()
            .map(|(i, row)| {
                if i == 0 {
                    let mut r = vec![F::ZERO; row.len()];
                    r[0] = F::ONE;
                    r
                } else {
                    let mut r = vec![F::ZERO; row.len()];
                    r[1..].copy_from_slice(&row[1..]);
                    r
                }
            })
            .collect()
    }

    fn make_v_w<F: PrimeField>(m: &Matrix<F>) -> (Vec<F>, Vec<F>) {
        let v = m[0][1..].to_vec();
        let w: Vec<F> = m.iter().skip(1).map(|row| row[0]).collect();
        (v, w)
    }

    fn make_double_prime<F: PrimeField>(m: &Matrix<F>, m_hat_inv: &Matrix<F>) -> Matrix<F> {
        let (v, w) = make_v_w(m);
        let w_hat = left_apply_matrix(m_hat_inv, &w);
        m.iter()
            .enumerate()
            .map(|(i, row)| {
                if i == 0 {
                    let mut r = Vec::with_capacity(row.len());
                    r.push(row[0]);
                    r.extend(&v);
                    r
                } else {
                    let mut r = vec![F::ZERO; row.len()];
                    r[0] = w_hat[i - 1];
                    r[i] = F::ONE;
                    r
                }
            })
            .collect()
    }

    fn derive_mds_matrices<F: PrimeField>(m: Matrix<F>) -> MdsMatrices<F> {
        let m_inv = invert(&m).unwrap();
        let m_hat = minor(&m, 0, 0);
        let m_hat_inv = invert(&m_hat).unwrap();
        let m_prime = make_prime(&m);
        let m_double_prime = make_double_prime(&m, &m_hat_inv);
        MdsMatrices {
            m,
            m_inv,
            _m_hat: m_hat,
            _m_hat_inv: m_hat_inv,
            m_prime,
            m_double_prime,
        }
    }

    // --- Sparse matrix ---

    #[derive(Clone)]
    struct SparseMatrix<F: PrimeField> {
        w_hat: Vec<F>,
        v_rest: Vec<F>,
    }

    fn mat_mul<F: PrimeField>(a: &Matrix<F>, b: &Matrix<F>) -> Option<Matrix<F>> {
        if rows(a) != columns(b) {
            return None;
        }
        let b_t = transpose(b);
        let res: Matrix<F> = a
            .iter()
            .map(|ar| {
                (0..columns(b))
                    .map(|j| {
                        let mut sum = F::ZERO;
                        for (i, &v) in ar.iter().enumerate() {
                            let mut t = v;
                            t.mul_assign(&b_t[j][i]);
                            sum.add_assign(&t);
                        }
                        sum
                    })
                    .collect()
            })
            .collect();
        Some(res)
    }

    fn factor_to_sparse<F: PrimeField>(
        base: &Matrix<F>,
        n: usize,
    ) -> (Matrix<F>, Vec<SparseMatrix<F>>) {
        let mut curr = base.clone();
        let mut sparse_matrices = Vec::new();
        for _ in 0..n {
            let derived = derive_mds_matrices(curr);
            let m_dd = &derived.m_double_prime;
            let size = rows(m_dd);
            let w_hat: Vec<F> = (0..size).map(|i| m_dd[i][0]).collect();
            let v_rest = m_dd[0][1..].to_vec();
            sparse_matrices.push(SparseMatrix { w_hat, v_rest });
            curr = mat_mul(base, &derived.m_prime).unwrap();
        }
        sparse_matrices.reverse();
        (curr, sparse_matrices)
    }

    // --- Quintic S-box ---

    fn quintic_s_box<F: PrimeField>(x: &mut F, pre: Option<&F>, post: Option<&F>) {
        if let Some(p) = pre {
            x.add_assign(p);
        }
        let mut t = *x;
        t = t.square();
        t = t.square();
        x.mul_assign(&t);
        if let Some(p) = post {
            x.add_assign(p);
        }
    }

    // --- Compress round constants ---

    fn compress_round_constants<F: PrimeField>(
        width: usize,
        full_rounds: usize,
        partial_rounds: usize,
        round_constants: &[F],
        mds: &MdsMatrices<F>,
        partial_preprocessed: usize,
    ) -> Vec<F> {
        let inv = &mds.m_inv;
        let mut res = Vec::new();
        let round_keys = |r: usize| &round_constants[r * width..(r + 1) * width];
        let half_full = full_rounds / 2;
        let unpreprocessed = partial_rounds - partial_preprocessed;
        let end = if unpreprocessed > 0 {
            half_full
        } else {
            half_full - 1
        };
        res.extend(round_keys(0));
        for i in 0..end {
            let next = round_keys(i + 1);
            res.extend(left_apply_matrix(inv, next));
        }
        let mut partial_keys = Vec::new();
        let final_round = half_full + partial_rounds;
        let final_key = round_keys(final_round).to_vec();
        let round_acc = (0..partial_preprocessed)
            .map(|i| round_keys(final_round - i - 1))
            .fold(final_key, |acc, prev| {
                let mut inv_acc = left_apply_matrix(inv, &acc);
                partial_keys.push(inv_acc[0]);
                inv_acc[0] = F::ZERO;
                vec_add(prev, &inv_acc)
            });
        for i in 1..unpreprocessed {
            res.extend(round_keys(half_full + i));
        }
        res.extend(left_apply_matrix(inv, &round_acc));
        while let Some(k) = partial_keys.pop() {
            res.push(k);
        }
        for i in 1..half_full {
            let start = half_full + partial_rounds;
            res.extend(left_apply_matrix(inv, round_keys(i + start)));
        }
        res
    }

    // --- Poseidon constants (arity 2, Strength::Standard) ---

    struct PoseidonConstants {
        compressed_round_constants: Vec<Fq>,
        mds_m: Matrix<Fq>,
        pre_sparse: Matrix<Fq>,
        sparse: Vec<SparseMatrix<Fq>>,
        half_full_rounds: usize,
        _partial_rounds: usize,
        width: usize,
    }

    /// Round numbers for arity 2: must match nova-snark exactly (round_numbers_base(2) = (8, 55)).
    const ARITY: usize = 2;

    fn build_constants() -> PoseidonConstants {
        let width = ARITY + 1; // 3
                               // Match Nova Strength::Standard: round_numbers_base(2) = (8, 55).
        let (full_rounds, partial_rounds) = round_numbers_base(ARITY);
        let mds = generate_mds::<Fq>(width);
        let round_constants = round_constants_for_params::<Fq>(ARITY, full_rounds, partial_rounds);
        let mds_matrices = derive_mds_matrices(mds);
        let compressed = compress_round_constants(
            width,
            full_rounds,
            partial_rounds,
            &round_constants,
            &mds_matrices,
            partial_rounds,
        );
        let m_t = transpose(&mds_matrices.m);
        let (pre_sparse, sparse) = factor_to_sparse(&m_t, partial_rounds);
        PoseidonConstants {
            compressed_round_constants: compressed,
            mds_m: mds_matrices.m,
            pre_sparse,
            sparse,
            half_full_rounds: full_rounds / 2,
            _partial_rounds: partial_rounds,
            width,
        }
    }

    static CONSTANTS: once_cell::sync::Lazy<PoseidonConstants> =
        once_cell::sync::Lazy::new(build_constants);

    // --- IOPattern value (domain tag for sponge capacity), same as Nova's Hasher ---
    // Hasher.update(a): x_i = x_i * x; state += x_i * a. Then finish_op calls update(op_value).

    const HASHER_BASE: u128 = (0u128).wrapping_sub(159);

    fn io_pattern_value(absorb: u32, squeeze: u32, domain_separator: u32) -> u128 {
        let x = HASHER_BASE;
        let absorb_val = absorb + (1 << 31);
        let squeeze_val = squeeze;
        // First op (absorb): x_i becomes x, state += x * absorb_val
        let mut x_i = x;
        let mut state = x_i.wrapping_mul(absorb_val as u128);
        // Second op (squeeze): x_i becomes x^2, state += x^2 * squeeze_val
        x_i = x_i.wrapping_mul(x);
        state = state.wrapping_add(x_i.wrapping_mul(squeeze_val as u128));
        // finalize(domain_separator): x_i becomes x^3, state += x^3 * domain_separator
        x_i = x_i.wrapping_mul(x);
        state = state.wrapping_add(x_i.wrapping_mul(domain_separator as u128));
        state
    }

    fn scalar_from_u128(v: u128) -> Fq {
        let mut repr = <Fq as PrimeField>::Repr::default();
        repr.as_mut()[..16].copy_from_slice(&v.to_le_bytes());
        Fq::from_repr(repr).unwrap()
    }

    // --- Permutation (hash_optimized_static) ---

    fn permute(state: &mut [Fq], c: &PoseidonConstants, offset: &mut usize) {
        fn product_mds<F: PrimeField>(s: &mut [F], m: &Matrix<F>) {
            let r = left_apply_matrix(m, s);
            s.copy_from_slice(&r);
        }
        fn product_mds_with_matrix<F: PrimeField>(s: &mut [F], m: &Matrix<F>) {
            let size = s.len();
            let mut result = vec![F::ZERO; size];
            for (j, val) in result.iter_mut().enumerate() {
                for (i, row) in m.iter().enumerate() {
                    let mut tmp = row[j];
                    tmp.mul_assign(&s[i]);
                    val.add_assign(&tmp);
                }
            }
            s.copy_from_slice(&result);
        }
        fn product_sparse<F: PrimeField>(s: &mut [F], sp: &SparseMatrix<F>) {
            let mut out = vec![F::ZERO; s.len()];
            for (i, w) in sp.w_hat.iter().enumerate() {
                let mut t = *w;
                t.mul_assign(&s[i]);
                out[0].add_assign(&t);
            }
            for j in 1..s.len() {
                out[j] = s[j];
                let mut t = sp.v_rest[j - 1];
                t.mul_assign(&s[0]);
                out[j].add_assign(&t);
            }
            s.copy_from_slice(&out);
        }

        // Initial ARK
        for (i, rc) in c.compressed_round_constants[*offset..*offset + c.width]
            .iter()
            .enumerate()
        {
            state[i].add_assign(rc);
        }
        *offset += c.width;

        // First half full rounds: all with post-round keys.
        // Last round of this half uses pre_sparse matrix (matches Nova's round_product_mds).
        let sparse_offset = c.half_full_rounds - 1;
        for round in 0..c.half_full_rounds {
            let keys = &c.compressed_round_constants[*offset..*offset + c.width];
            for (s, k) in state.iter_mut().zip(keys.iter()) {
                quintic_s_box(s, None, Some(k));
            }
            *offset += c.width;
            if round == sparse_offset {
                product_mds_with_matrix(state, &c.pre_sparse);
            } else {
                product_mds(state, &c.mds_m);
            }
        }

        // Partial rounds: 1 post-round key each + sparse MDS
        for sp in &c.sparse {
            let k = &c.compressed_round_constants[*offset];
            *offset += 1;
            quintic_s_box(&mut state[0], None, Some(k));
            product_sparse(state, sp);
        }

        // Second half full rounds: all but last with post-round keys
        for _ in 1..c.half_full_rounds {
            let keys = &c.compressed_round_constants[*offset..*offset + c.width];
            for (s, k) in state.iter_mut().zip(keys.iter()) {
                quintic_s_box(s, None, Some(k));
            }
            *offset += c.width;
            product_mds(state, &c.mds_m);
        }

        // Last full round: S-box only, no post-round keys
        for s in state.iter_mut() {
            quintic_s_box(s, None, None);
        }
        product_mds(state, &c.mds_m);
    }

    // --- Sponge: absorb then squeeze (same as Nova Sponge API) ---

    #[allow(unused_assignments)]
    pub(super) fn hash_internal(inputs: &[Fq], pattern_absorb: u32, pattern_squeeze: u32) -> Fq {
        let tag = io_pattern_value(pattern_absorb, pattern_squeeze, 0);
        let cap = scalar_from_u128(tag);
        let mut state = vec![cap, Fq::ZERO, Fq::ZERO];
        let rate = 2;
        let mut offset = 0usize;

        // Absorb: add inputs to rate positions; permute when rate is full
        let mut absorb_pos = 0usize;
        for &x in inputs {
            if absorb_pos == rate {
                offset = 0;
                permute(state.as_mut(), &CONSTANTS, &mut offset);
                absorb_pos = 0;
            }
            state[1 + absorb_pos].add_assign(&x);
            absorb_pos += 1;
        }

        // Switch to squeezing: permute if we had partial absorb or need to refill
        offset = 0;
        permute(state.as_mut(), &CONSTANTS, &mut offset);

        // Squeeze one element (rate position 0 = state[1])
        state[1]
    }
}

#[cfg(not(feature = "nova_poseidon"))]
use standalone_poseidon::hash_internal;

#[cfg(not(feature = "nova_poseidon"))]
#[cfg(test)]
use standalone_poseidon::round_numbers_base;

// --- Public API ---

/// Domain separation tag constants (same as kontor-crypto).
pub mod domain_tags {
    pub const LEAF: u64 = 1;
    pub const NODE: u64 = 2;
    pub const CHALLENGE: u64 = 6;
    pub const STATE_UPDATE: u64 = 7;
    pub const ROOT_COMMITMENT: u64 = 8;
    pub const CHALLENGE_PER_FILE: u64 = 9;
    pub const CHALLENGE_ID: u64 = 10;

    use super::FieldElement;

    pub fn leaf() -> FieldElement {
        FieldElement::from(LEAF)
    }
    pub fn node() -> FieldElement {
        FieldElement::from(NODE)
    }
    pub fn challenge() -> FieldElement {
        FieldElement::from(CHALLENGE)
    }
    pub fn state_update() -> FieldElement {
        FieldElement::from(STATE_UPDATE)
    }
    pub fn root_commitment() -> FieldElement {
        FieldElement::from(ROOT_COMMITMENT)
    }
    pub fn challenge_per_file() -> FieldElement {
        FieldElement::from(CHALLENGE_PER_FILE)
    }
    pub fn challenge_id() -> FieldElement {
        FieldElement::from(CHALLENGE_ID)
    }
}

/// Two-to-one Poseidon hash (2 inputs → 1 output).
#[cfg(not(feature = "nova_poseidon"))]
pub fn poseidon_hash2(left: Fq, right: Fq) -> Fq {
    hash_internal(&[left, right], 2, 1)
}

/// Domain-separated Poseidon hash: tag + two field elements → 1 output.
#[cfg(not(feature = "nova_poseidon"))]
pub fn poseidon_hash_tagged(tag: Fq, x: Fq, y: Fq) -> Fq {
    hash_internal(&[tag, x, y], 3, 1)
}

#[cfg(feature = "nova_poseidon")]
mod nova_delegate {
    use super::FieldElement;
    use generic_array::typenum::U2;
    use nova_snark::frontend::gadgets::poseidon::{
        IOPattern, PoseidonConstants, Simplex, Sponge, SpongeAPI, SpongeOp, SpongeTrait, Strength,
    };
    use once_cell::sync::Lazy;

    static C: Lazy<PoseidonConstants<FieldElement, U2>> =
        Lazy::new(|| Sponge::<FieldElement, U2>::api_constants(Strength::Standard));
    static IO_2: Lazy<IOPattern> =
        Lazy::new(|| IOPattern(vec![SpongeOp::Absorb(2), SpongeOp::Squeeze(1)]));
    static IO_3: Lazy<IOPattern> =
        Lazy::new(|| IOPattern(vec![SpongeOp::Absorb(3), SpongeOp::Squeeze(1)]));

    pub fn poseidon_hash2(left: FieldElement, right: FieldElement) -> FieldElement {
        let mut sponge = Sponge::<FieldElement, U2>::new_with_constants(&C, Simplex);
        let mut acc = ();
        sponge.start(IO_2.clone(), None, &mut acc);
        SpongeAPI::absorb(&mut sponge, 2, &[left, right], &mut acc);
        let out = SpongeAPI::squeeze(&mut sponge, 1, &mut acc);
        sponge.finish(&mut acc).expect("sponge finish");
        out[0]
    }

    pub fn poseidon_hash_tagged(
        tag: FieldElement,
        x: FieldElement,
        y: FieldElement,
    ) -> FieldElement {
        let mut sponge = Sponge::<FieldElement, U2>::new_with_constants(&C, Simplex);
        let mut acc = ();
        sponge.start(IO_3.clone(), None, &mut acc);
        SpongeAPI::absorb(&mut sponge, 3, &[tag, x, y], &mut acc);
        let out = SpongeAPI::squeeze(&mut sponge, 1, &mut acc);
        sponge.finish(&mut acc).expect("sponge finish");
        out[0]
    }
}

#[cfg(feature = "nova_poseidon")]
pub use nova_delegate::{poseidon_hash2, poseidon_hash_tagged};

#[cfg(test)]
mod tests {
    use super::*;

    /// Round numbers for arity 2 must match Nova (same formula as round_numbers_base).
    #[cfg(not(feature = "nova_poseidon"))]
    #[test]
    fn round_numbers_arity2_matches_nova() {
        let (rf, rp) = round_numbers_base(2);
        assert_eq!(rf, 8, "full rounds from calc_round_numbers(3, true)");
        assert_eq!(rp, 55, "partial rounds from calc_round_numbers(3, true)");
    }

    /// Known-answer regression: standalone Poseidon must match Nova's output.
    /// Expected values are Nova's canonical output. If this test fails, the
    /// standalone implementation diverges from Nova and the WASM path is broken.
    #[cfg(not(feature = "nova_poseidon"))]
    #[test]
    fn poseidon_known_answer_standalone() {
        use ff::PrimeField;

        fn fq_from_hex(hex: &str) -> Fq {
            let hex = hex.trim_start_matches("0x");
            let mut buf = [0u8; 32];
            for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
                let s = core::str::from_utf8(chunk).unwrap();
                buf[31 - i] = u8::from_str_radix(s, 16).unwrap();
            }
            let mut repr = <Fq as PrimeField>::Repr::default();
            repr.as_mut().copy_from_slice(&buf);
            Fq::from_repr(repr).unwrap()
        }

        assert_eq!(
            poseidon_hash2(Fq::from(0u64), Fq::from(0u64)),
            fq_from_hex("38ec69788c896550d69fb76411058e72798b21bcaaae2ad06101e9dc558b5dbd"),
            "poseidon_hash2(0,0) must match Nova"
        );
        assert_eq!(
            poseidon_hash_tagged(domain_tags::leaf(), Fq::from(1u64), Fq::from(2u64)),
            fq_from_hex("2eb3923b358306dc6af5240a87e8ea32ec23a2b4cc99932af880d75a86021495"),
            "poseidon_hash_tagged(leaf,1,2) must match Nova"
        );
    }

    #[test]
    fn domain_separation() {
        let x = Fq::from(42u64);
        let y = Fq::from(123u64);
        let h_leaf = poseidon_hash_tagged(domain_tags::leaf(), x, y);
        let h_node = poseidon_hash_tagged(domain_tags::node(), x, y);
        assert_ne!(h_leaf, h_node);
    }

    #[test]
    fn hash2_deterministic() {
        let a = Fq::from(1u64);
        let b = Fq::from(2u64);
        assert_eq!(poseidon_hash2(a, b), poseidon_hash2(a, b));
    }
}
