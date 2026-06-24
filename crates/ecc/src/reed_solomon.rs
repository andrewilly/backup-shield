// BackupShield – Cross-platform incremental backup with data integrity and auto-repair
// Copyright (c) 2026 André Willy Rizzo. All rights reserved.
// Concept and original idea by André Willy Rizzo.

//! # Reed-Solomon Error Correction over GF(256)
//!
//! This module implements a pure Rust Reed-Solomon erasure coding scheme using
//! Vandermonde matrices over GF(256) with the irreducible polynomial
//! x^8 + x^4 + x^3 + x^2 + 1 (0x11D).
//!
//! The implementation supports:
//! - Encoding: compute parity shards from data shards
//! - Reconstruction: recover missing data/parity shards from available ones

// ---------------------------------------------------------------------------
// GF(256) Arithmetic
// ---------------------------------------------------------------------------

/// The irreducible polynomial for GF(256): x^8 + x^4 + x^3 + x^2 + 1
const GF_POLY: u16 = 0x11D;

/// GF(256) arithmetic helper module.
///
/// All operations use the field defined by the polynomial `x^8 + x^4 + x^3 + x^2 + 1`
/// (0x11D). Lookup tables are built at construction time for performance.
pub struct Gf256 {
    /// Exponent table: EXP_TABLE[i] = alpha^i in GF(256), for i in 0..511.
    /// The table is duplicated to avoid modular reduction during multiplication.
    pub exp_table: [u8; 512],
    /// Logarithm table: LOG_TABLE[v] = log_alpha(v), for v in 1..=255.
    /// LOG_TABLE[0] is unused (set to 0) and should never be accessed for v=0.
    pub log_table: [u8; 256],
}

impl Gf256 {
    /// Build the GF(256) exponent and log tables from the generating polynomial.
    pub fn new() -> Self {
        let mut exp_table = [0u8; 512];
        let mut log_table = [0u8; 256];

        let mut x: u16 = 1;
        for i in 0..255 {
            exp_table[i] = x as u8;
            log_table[x as usize] = i as u8;
            x <<= 1;
            if x >= 256 {
                x ^= GF_POLY;
            }
        }
        // Duplicate the first 256 entries so we can look up alpha^(i+1) without
        // modular reduction when i = 254 (alpha^255 = alpha^0 = 1).
        for i in 255..512 {
            exp_table[i] = exp_table[i - 255];
        }

        Self {
            exp_table,
            log_table,
        }
    }

    /// Multiply two elements in GF(256).
    #[inline]
    pub fn gf_mul(&self, a: u8, b: u8) -> u8 {
        if a == 0 || b == 0 {
            0
        } else {
            self.exp_table
                [(self.log_table[a as usize] as usize + self.log_table[b as usize] as usize) % 255]
        }
    }

    /// Divide two elements in GF(256). Returns `Err(EccError::DivisionByZero)` if `b == 0`.
    #[inline]
    pub fn gf_div(&self, a: u8, b: u8) -> std::result::Result<u8, crate::EccError> {
        if b == 0 {
            return Err(crate::EccError::DivisionByZero);
        }
        if a == 0 {
            Ok(0)
        } else {
            let log_a = self.log_table[a as usize] as usize;
            let log_b = self.log_table[b as usize] as usize;
            Ok(self.exp_table[(log_a + 255 - log_b) % 255])
        }
    }

    /// Compute the multiplicative inverse of an element in GF(256).
    /// Returns `Err(EccError::InverseOfZero)` if `a == 0`.
    #[inline]
    pub fn gf_inv(&self, a: u8) -> std::result::Result<u8, crate::EccError> {
        if a == 0 {
            return Err(crate::EccError::InverseOfZero);
        }
        Ok(self.exp_table[255 - self.log_table[a as usize] as usize])
    }

    /// Compute `a^n` in GF(256).
    #[inline]
    pub fn gf_pow(&self, a: u8, n: usize) -> u8 {
        if n == 0 {
            1
        } else if a == 0 {
            0
        } else {
            let log_a = self.log_table[a as usize] as usize;
            self.exp_table[(log_a * n) % 255]
        }
    }
}

impl Default for Gf256 {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// GF(256) Matrix
// ---------------------------------------------------------------------------

/// A matrix over GF(256) for use in encoding and reconstruction operations.
pub struct Matrix {
    rows: usize,
    cols: usize,
    data: Vec<u8>,
    gf: Gf256,
}

impl Matrix {
    /// Create a new `rows × cols` matrix initialized to zeros.
    pub fn new(rows: usize, cols: usize, gf: Gf256) -> Self {
        Self {
            rows,
            cols,
            data: vec![0u8; rows * cols],
            gf,
        }
    }

    /// Get the element at (row, col).
    #[inline]
    pub fn get(&self, row: usize, col: usize) -> u8 {
        self.data[row * self.cols + col]
    }

    /// Set the element at (row, col).
    #[inline]
    pub fn set(&mut self, row: usize, col: usize, val: u8) {
        self.data[row * self.cols + col] = val;
    }

    /// Return the number of rows.
    pub fn rows(&self) -> usize {
        self.rows
    }

    /// Return the number of columns.
    pub fn cols(&self) -> usize {
        self.cols
    }

    /// Multiply two matrices over GF(256). `self` is `m × n`, `other` is `n × p`,
    /// yielding an `m × p` result.
    pub fn multiply(&self, other: &Matrix) -> Matrix {
        assert_eq!(
            self.cols, other.rows,
            "Matrix dimensions mismatch for multiplication"
        );
        let mut result = Matrix::new(self.rows, other.cols, Gf256::new());

        for i in 0..self.rows {
            for j in 0..other.cols {
                let mut sum: u8 = 0;
                for k in 0..self.cols {
                    sum = self.gf.gf_mul(sum, 1) ^ self.gf.gf_mul(self.get(i, k), other.get(k, j));
                }
                result.set(i, j, sum);
            }
        }

        result
    }

    /// Compute the inverse of a square matrix over GF(256) using Gauss-Jordan elimination.
    /// Returns `Err` if the matrix is singular.
    pub fn invert(&self) -> Result<Matrix, String> {
        if self.rows != self.cols {
            return Err("Cannot invert a non-square matrix".to_string());
        }
        let n = self.rows;

        // Augmented matrix [self | I]
        let mut aug = Matrix::new(n, 2 * n, Gf256::new());
        for i in 0..n {
            for j in 0..n {
                aug.set(i, j, self.get(i, j));
            }
            aug.set(i, n + i, 1);
        }

        // Forward elimination with partial pivoting
        for col in 0..n {
            // Find pivot row
            let mut pivot_row = None;
            for row in col..n {
                if aug.get(row, col) != 0 {
                    pivot_row = Some(row);
                    break;
                }
            }
            let pivot_row = pivot_row
                .ok_or_else(|| format!("Matrix is singular: zero column at position {}", col))?;

            // Swap current row with pivot row
            if pivot_row != col {
                for j in 0..2 * n {
                    let tmp = aug.get(col, j);
                    aug.set(col, j, aug.get(pivot_row, j));
                    aug.set(pivot_row, j, tmp);
                }
            }

            // Scale pivot row so pivot element becomes 1
            let pivot_val = aug.get(col, col);
            let pivot_inv = self
                .gf
                .gf_inv(pivot_val)
                .map_err(|e| format!("Singular matrix at column {}: {}", col, e))?;
            for j in 0..2 * n {
                aug.set(col, j, self.gf.gf_mul(aug.get(col, j), pivot_inv));
            }

            // Eliminate all other rows
            for row in 0..n {
                if row == col {
                    continue;
                }
                let factor = aug.get(row, col);
                if factor == 0 {
                    continue;
                }
                for j in 0..2 * n {
                    let val = aug.get(row, j) ^ self.gf.gf_mul(factor, aug.get(col, j));
                    aug.set(row, j, val);
                }
            }
        }

        // Extract the right half as the inverse
        let mut inv = Matrix::new(n, n, Gf256::new());
        for i in 0..n {
            for j in 0..n {
                inv.set(i, j, aug.get(i, n + j));
            }
        }

        Ok(inv)
    }
}

// ---------------------------------------------------------------------------
// Vandermonde Matrix Construction
// ---------------------------------------------------------------------------

/// Build a Vandermonde matrix of size `rows × cols` over GF(256).
///
/// The entry at (i, j) is `alpha^(i * j)` where alpha is the primitive element
/// of the field (2 in this construction, since exp_table is built from x=1
/// doubling each step).
fn vandermonde(rows: usize, cols: usize, gf: &Gf256) -> Matrix {
    let mut mat = Matrix::new(rows, cols, Gf256::new());
    for i in 0..rows {
        for j in 0..cols {
            // Entry is alpha^(i*j) which is gf_pow(2, i*j), but since our
            // exp_table uses alpha=2 as generator, we can use exp_table directly.
            // exp_table[k] = alpha^k where alpha is the primitive element.
            if i == 0 || j == 0 {
                mat.set(i, j, 1);
            } else {
                mat.set(i, j, gf.exp_table[(i * j) % 255]);
            }
        }
    }
    mat
}

/// Build the encoding matrix for Reed-Solomon.
///
/// The encoding matrix is a `(data_shards + parity_shards) × data_shards` matrix
/// where the top `data_shards × data_shards` sub-matrix is the identity and the
/// bottom `parity_shards × data_shards` sub-matrix consists of rows of a
/// Vandermonde matrix.
fn build_encoding_matrix(data_shards: usize, parity_shards: usize, gf: &Gf256) -> Matrix {
    let total = data_shards + parity_shards;
    let vand = vandermonde(total, data_shards, gf);

    let mut mat = Matrix::new(total, data_shards, Gf256::new());

    // Top part is identity
    for i in 0..data_shards {
        for j in 0..data_shards {
            mat.set(i, j, if i == j { 1 } else { 0 });
        }
    }

    // Bottom part is Vandermonde rows (skip first `data_shards` rows of Vandermonde)
    for i in 0..parity_shards {
        for j in 0..data_shards {
            mat.set(data_shards + i, j, vand.get(data_shards + i, j));
        }
    }

    mat
}

// ---------------------------------------------------------------------------
// ReedSolomon
// ---------------------------------------------------------------------------

/// Reed-Solomon erasure codec over GF(256).
///
/// Splits data into `data_shards` equal-length slices and computes
/// `parity_shards` parity slices. Up to `parity_shards` shards can be lost
/// and recovered.
pub struct ReedSolomon {
    /// Number of data shards.
    pub data_shards: usize,
    /// Number of parity shards.
    pub parity_shards: usize,
    /// The encoding matrix (total_shards × data_shards).
    encoding_matrix: Matrix,
    /// GF(256) lookup tables.
    gf: Gf256,
}

impl ReedSolomon {
    /// Create a new Reed-Solomon codec.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `data_shards` is 0
    /// - `parity_shards` is 0
    /// - `data_shards + parity_shards > 256` (exceeds GF(256) field size)
    pub fn new(data_shards: usize, parity_shards: usize) -> Result<Self, String> {
        if data_shards == 0 {
            return Err("data_shards must be at least 1".to_string());
        }
        if parity_shards == 0 {
            return Err("parity_shards must be at least 1".to_string());
        }
        if data_shards + parity_shards > 256 {
            return Err(format!(
                "data_shards + parity_shards = {} exceeds 256 (GF(256) field size)",
                data_shards + parity_shards
            ));
        }

        let gf = Gf256::new();
        let encoding_matrix = build_encoding_matrix(data_shards, parity_shards, &gf);

        Ok(Self {
            data_shards,
            parity_shards,
            encoding_matrix,
            gf,
        })
    }

    /// Encode data shards into parity shards.
    ///
    /// Takes `data_shards` slices of equal length and returns `parity_shards`
    /// parity slices.
    ///
    /// # Errors
    ///
    /// Returns an error if the number of input slices does not equal
    /// `data_shards`, or if the slices have differing lengths.
    pub fn encode(&self, data: &[Vec<u8>]) -> Result<Vec<Vec<u8>>, String> {
        if data.len() != self.data_shards {
            return Err(format!(
                "Expected {} data shards, got {}",
                self.data_shards,
                data.len()
            ));
        }

        let shard_len = data.first().map(|s| s.len()).unwrap_or(0);
        for (i, shard) in data.iter().enumerate() {
            if shard.len() != shard_len {
                return Err(format!(
                    "Shard {} has length {}, expected {} (all shards must be equal length)",
                    i,
                    shard.len(),
                    shard_len
                ));
            }
        }

        if shard_len == 0 {
            return Ok(vec![vec![]; self.parity_shards]);
        }

        // Extract the parity rows of the encoding matrix
        // Row (data_shards + p) for p in 0..parity_shards
        let mut parity = vec![vec![0u8; shard_len]; self.parity_shards];

        for p in 0..self.parity_shards {
            let matrix_row = self.data_shards + p;
            for d in 0..self.data_shards {
                let coeff = self.encoding_matrix.get(matrix_row, d);
                for byte_idx in 0..shard_len {
                    parity[p][byte_idx] ^= self.gf.gf_mul(coeff, data[d][byte_idx]);
                }
            }
        }

        Ok(parity)
    }

    /// Encode data shards into parity shards (alias for `encode`).
    pub fn encode_single(&self, data_shards: &[Vec<u8>]) -> Result<Vec<Vec<u8>>, String> {
        self.encode(data_shards)
    }

    /// Reconstruct missing shards in place.
    ///
    /// `shards` is a slice of length `data_shards + parity_shards`. Each element
    /// is `Some(data)` if the shard is available/valid, or `None` if the shard
    /// is missing/corrupt. `shard_present[i]` should be `true` if `shards[i]`
    /// is present.
    ///
    /// After calling, all `None` entries in `shards` will be filled with the
    /// reconstructed data.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `shards.len()` != `data_shards + parity_shards`
    /// - `shard_present.len()` != `data_shards + parity_shards`
    /// - Fewer than `data_shards` shards are present (not enough information
    ///   to reconstruct)
    /// - Present shards have inconsistent lengths
    pub fn reconstruct(
        &self,
        shards: &mut [Option<Vec<u8>>],
        shard_present: &[bool],
    ) -> Result<(), String> {
        let total = self.data_shards + self.parity_shards;

        if shards.len() != total {
            return Err(format!(
                "shards.len() = {}, expected {}",
                shards.len(),
                total
            ));
        }
        if shard_present.len() != total {
            return Err(format!(
                "shard_present.len() = {}, expected {}",
                shard_present.len(),
                total
            ));
        }

        // Count present shards and collect their indices
        let present_indices: Vec<usize> = shard_present
            .iter()
            .enumerate()
            .filter(|(_, &present)| present)
            .map(|(i, _)| i)
            .collect();

        if present_indices.len() < self.data_shards {
            return Err(format!(
                "Not enough shards to reconstruct: {} present, need at least {}",
                present_indices.len(),
                self.data_shards
            ));
        }

        // If all shards are present, nothing to do
        let missing_indices: Vec<usize> = shard_present
            .iter()
            .enumerate()
            .filter(|(_, &present)| !present)
            .map(|(i, _)| i)
            .collect();

        if missing_indices.is_empty() {
            return Ok(());
        }

        // Determine shard length from available shards
        let shard_len = present_indices
            .iter()
            .filter_map(|&i| shards[i].as_ref().map(|s| s.len()))
            .next()
            .unwrap_or(0);

        // Verify consistency and that present shards have data
        for &i in &present_indices {
            match &shards[i] {
                Some(data) => {
                    if data.len() != shard_len {
                        return Err(format!(
                            "Shard {} has length {}, expected {}",
                            i,
                            data.len(),
                            shard_len
                        ));
                    }
                }
                None => {
                    return Err(format!("Shard {} marked as present but has no data", i));
                }
            }
        }

        // We only need data_shards present shards for reconstruction.
        // Use the first data_shards present ones.
        let use_indices: Vec<usize> = present_indices[..self.data_shards].to_vec();

        // Step 1: Build the sub-matrix from the encoding matrix rows corresponding
        // to the present shards we're using.
        let mut sub_matrix = Matrix::new(self.data_shards, self.data_shards, Gf256::new());
        for (out_row, &src_row) in use_indices.iter().enumerate() {
            for col in 0..self.data_shards {
                sub_matrix.set(out_row, col, self.encoding_matrix.get(src_row, col));
            }
        }

        // Step 2: Invert the sub-matrix
        let inv_matrix = sub_matrix
            .invert()
            .map_err(|e| format!("Failed to invert sub-matrix for reconstruction: {}", e))?;

        // Step 3: Recover all shards by multiplying the inverse matrix with
        // present shard data, then use the encoding matrix to fill in all
        // total shards.
        //
        // First, recover the original data shards:
        // data[j] = sum over i of inv_matrix[j][i] * present_shard[i]
        let present_data: Vec<&[u8]> = use_indices
            .iter()
            .map(|&i| shards[i].as_ref().unwrap().as_slice())
            .collect();

        let mut recovered_data = vec![vec![0u8; shard_len]; self.data_shards];
        for j in 0..self.data_shards {
            for i in 0..self.data_shards {
                let coeff = inv_matrix.get(j, i);
                for byte_idx in 0..shard_len {
                    recovered_data[j][byte_idx] ^= self.gf.gf_mul(coeff, present_data[i][byte_idx]);
                }
            }
        }

        // Now reconstruct all shards using the encoding matrix
        for &idx in &missing_indices {
            let mut shard_data = vec![0u8; shard_len];
            for d in 0..self.data_shards {
                let coeff = self.encoding_matrix.get(idx, d);
                for byte_idx in 0..shard_len {
                    shard_data[byte_idx] ^= self.gf.gf_mul(coeff, recovered_data[d][byte_idx]);
                }
            }
            shards[idx] = Some(shard_data);
        }

        // Also fill in any present data shards that might have been missing from
        // the original data set but are in the first data_shards positions
        // (they should already be present, but let's make sure the data shards
        // positions are also filled).
        for d in 0..self.data_shards {
            if shards[d].is_none() {
                shards[d] = Some(recovered_data[d].clone());
            }
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gf256_mul_identity() {
        let gf = Gf256::new();
        for v in 1u8..=255 {
            assert_eq!(gf.gf_mul(v, 1), v);
            assert_eq!(gf.gf_mul(1, v), v);
        }
    }

    #[test]
    fn test_gf256_mul_zero() {
        let gf = Gf256::new();
        for v in 0u8..=255 {
            assert_eq!(gf.gf_mul(v, 0), 0);
            assert_eq!(gf.gf_mul(0, v), 0);
        }
    }

    #[test]
    fn test_gf256_mul_commutative() {
        let gf = Gf256::new();
        for a in 0u8..=255 {
            for b in a..=255u8 {
                assert_eq!(gf.gf_mul(a, b), gf.gf_mul(b, a));
            }
        }
    }

    #[test]
    fn test_gf256_mul_associative() {
        let gf = Gf256::new();
        for a in 1u8..=10 {
            for b in 1u8..=10 {
                for c in 1u8..=10 {
                    let ab_c = gf.gf_mul(gf.gf_mul(a, b), c);
                    let a_bc = gf.gf_mul(a, gf.gf_mul(b, c));
                    assert_eq!(ab_c, a_bc, "Associativity failed: ({}, {}, {})", a, b, c);
                }
            }
        }
    }

    #[test]
    fn test_gf256_div_inverse() {
        let gf = Gf256::new();
        for v in 1u8..=255 {
            let inv = gf.gf_inv(v).unwrap();
            let product = gf.gf_mul(v, inv);
            assert_eq!(product, 1, "a * a^-1 should be 1 for a={}", v);
        }
    }

    #[test]
    fn test_gf256_div_roundtrip() {
        let gf = Gf256::new();
        for a in 1u8..=255 {
            for b in 1u8..=255 {
                let div_result = gf.gf_div(a, b).unwrap();
                let product = gf.gf_mul(div_result, b);
                assert_eq!(product, a, "({} / {}) * {} != {}", a, b, b, a);
            }
        }
    }

    #[test]
    fn test_gf256_div_by_zero_returns_error() {
        let gf = Gf256::new();
        let result = gf.gf_div(42, 0);
        assert!(result.is_err(), "division by zero should return error");
        match result {
            Err(crate::EccError::DivisionByZero) => {} // expected
            other => panic!("expected DivisionByZero, got {:?}", other),
        }
    }

    #[test]
    fn test_gf256_inv_of_zero_returns_error() {
        let gf = Gf256::new();
        let result = gf.gf_inv(0);
        assert!(result.is_err(), "inverse of zero should return error");
        match result {
            Err(crate::EccError::InverseOfZero) => {} // expected
            other => panic!("expected InverseOfZero, got {:?}", other),
        }
    }

    #[test]
    fn test_gf256_pow() {
        let gf = Gf256::new();
        assert_eq!(gf.gf_pow(2, 0), 1);
        assert_eq!(gf.gf_pow(2, 1), 2);
        // 2^8 in GF(256) with polynomial 0x11D
        assert_eq!(gf.gf_pow(2, 8), 0x1D);
    }

    #[test]
    fn test_gf256_pow_order() {
        let gf = Gf256::new();
        // 2 is a generator, so 2^255 = 1
        assert_eq!(gf.gf_pow(2, 255), 1);
    }

    #[test]
    fn test_matrix_identity_invert() {
        let gf = Gf256::new();
        let n = 4;
        let mut mat = Matrix::new(n, n, gf);
        for i in 0..n {
            mat.set(i, i, 1);
        }
        let inv = mat.invert().unwrap();
        for i in 0..n {
            for j in 0..n {
                let expected = if i == j { 1 } else { 0 };
                assert_eq!(inv.get(i, j), expected);
            }
        }
    }

    #[test]
    fn test_matrix_multiply_identity() {
        let _gf = Gf256::new();
        let n = 3;
        let mut identity = Matrix::new(n, n, Gf256::new());
        for i in 0..n {
            identity.set(i, i, 1);
        }
        let mut mat = Matrix::new(n, n, Gf256::new());
        mat.set(0, 0, 1);
        mat.set(0, 1, 2);
        mat.set(0, 2, 3);
        mat.set(1, 0, 4);
        mat.set(1, 1, 5);
        mat.set(1, 2, 6);
        mat.set(2, 0, 7);
        mat.set(2, 1, 8);
        mat.set(2, 2, 9);

        let result = identity.multiply(&mat);
        for i in 0..n {
            for j in 0..n {
                assert_eq!(result.get(i, j), mat.get(i, j));
            }
        }
    }

    #[test]
    fn test_matrix_invert_roundtrip() {
        let gf = Gf256::new();
        let mut mat = Matrix::new(3, 3, gf);
        // Non-singular matrix
        mat.set(0, 0, 1);
        mat.set(0, 1, 2);
        mat.set(0, 2, 3);
        mat.set(1, 0, 4);
        mat.set(1, 1, 5);
        mat.set(1, 2, 6);
        mat.set(2, 0, 7);
        mat.set(2, 1, 8);
        mat.set(2, 2, 10); // not 9 to avoid singular

        let inv = mat.invert().unwrap();
        let product = mat.multiply(&inv);

        for i in 0..3 {
            for j in 0..3 {
                let expected = if i == j { 1 } else { 0 };
                assert_eq!(
                    product.get(i, j),
                    expected,
                    "Product[{}][{}] = {}, expected {}",
                    i,
                    j,
                    product.get(i, j),
                    expected
                );
            }
        }
    }

    #[test]
    fn test_reed_solomon_new_validation() {
        // Valid
        assert!(ReedSolomon::new(4, 2).is_ok());
        assert!(ReedSolomon::new(1, 1).is_ok());

        // Invalid
        assert!(ReedSolomon::new(0, 2).is_err());
        assert!(ReedSolomon::new(4, 0).is_err());
        assert!(ReedSolomon::new(200, 60).is_err()); // 260 > 256
    }

    #[test]
    fn test_encode_basic() {
        let rs = ReedSolomon::new(3, 2).unwrap();
        let data: Vec<Vec<u8>> = vec![vec![1, 2, 3, 4], vec![5, 6, 7, 8], vec![9, 10, 11, 12]];
        let parity = rs.encode(&data).unwrap();
        assert_eq!(parity.len(), 2);
        assert_eq!(parity[0].len(), 4);
        assert_eq!(parity[1].len(), 4);
    }

    #[test]
    fn test_encode_wrong_shard_count() {
        let rs = ReedSolomon::new(3, 2).unwrap();
        let data: Vec<Vec<u8>> = vec![vec![1, 2], vec![3, 4]];
        assert!(rs.encode(&data).is_err());
    }

    #[test]
    fn test_encode_unequal_lengths() {
        let rs = ReedSolomon::new(2, 1).unwrap();
        let data: Vec<Vec<u8>> = vec![vec![1, 2, 3], vec![4, 5]];
        assert!(rs.encode(&data).is_err());
    }

    #[test]
    fn test_encode_empty_shards() {
        let rs = ReedSolomon::new(2, 1).unwrap();
        let data: Vec<Vec<u8>> = vec![vec![], vec![]];
        let parity = rs.encode(&data).unwrap();
        assert_eq!(parity.len(), 1);
        assert!(parity[0].is_empty());
    }

    #[test]
    fn test_encode_single_alias() {
        let rs = ReedSolomon::new(3, 2).unwrap();
        let data: Vec<Vec<u8>> = vec![vec![1, 2, 3], vec![4, 5, 6], vec![7, 8, 9]];
        let parity1 = rs.encode(&data).unwrap();
        let parity2 = rs.encode_single(&data).unwrap();
        assert_eq!(parity1, parity2);
    }

    #[test]
    fn test_reconstruct_no_loss() {
        let rs = ReedSolomon::new(3, 2).unwrap();
        let data: Vec<Vec<u8>> = vec![vec![1, 2, 3], vec![4, 5, 6], vec![7, 8, 9]];
        let parity = rs.encode(&data).unwrap();

        let mut shards: Vec<Option<Vec<u8>>> = vec![None; 5];
        shards[0] = Some(data[0].clone());
        shards[1] = Some(data[1].clone());
        shards[2] = Some(data[2].clone());
        shards[3] = Some(parity[0].clone());
        shards[4] = Some(parity[1].clone());

        let shard_present = vec![true; 5];
        rs.reconstruct(&mut shards, &shard_present).unwrap();

        assert_eq!(shards[0].as_ref().unwrap(), &data[0]);
        assert_eq!(shards[1].as_ref().unwrap(), &data[1]);
        assert_eq!(shards[2].as_ref().unwrap(), &data[2]);
    }

    #[test]
    fn test_reconstruct_one_data_shard_lost() {
        let rs = ReedSolomon::new(3, 2).unwrap();
        let data: Vec<Vec<u8>> = vec![vec![1, 2, 3], vec![4, 5, 6], vec![7, 8, 9]];
        let parity = rs.encode(&data).unwrap();

        // Lose data shard 1
        let mut shards: Vec<Option<Vec<u8>>> = vec![None; 5];
        shards[0] = Some(data[0].clone());
        shards[1] = None; // lost
        shards[2] = Some(data[2].clone());
        shards[3] = Some(parity[0].clone());
        shards[4] = Some(parity[1].clone());

        let shard_present = vec![true, false, true, true, true];
        rs.reconstruct(&mut shards, &shard_present).unwrap();

        assert_eq!(shards[1].as_ref().unwrap(), &data[1]);
    }

    #[test]
    fn test_reconstruct_two_data_shards_lost() {
        let rs = ReedSolomon::new(3, 2).unwrap();
        let data: Vec<Vec<u8>> = vec![vec![10, 20, 30], vec![40, 50, 60], vec![70, 80, 90]];
        let parity = rs.encode(&data).unwrap();

        // Lose data shards 0 and 2
        let mut shards: Vec<Option<Vec<u8>>> = vec![None; 5];
        shards[0] = None; // lost
        shards[1] = Some(data[1].clone());
        shards[2] = None; // lost
        shards[3] = Some(parity[0].clone());
        shards[4] = Some(parity[1].clone());

        let shard_present = vec![false, true, false, true, true];
        rs.reconstruct(&mut shards, &shard_present).unwrap();

        assert_eq!(shards[0].as_ref().unwrap(), &data[0]);
        assert_eq!(shards[2].as_ref().unwrap(), &data[2]);
    }

    #[test]
    fn test_reconstruct_parity_shard_lost() {
        let rs = ReedSolomon::new(3, 2).unwrap();
        let data: Vec<Vec<u8>> = vec![vec![1, 2, 3], vec![4, 5, 6], vec![7, 8, 9]];
        let parity = rs.encode(&data).unwrap();

        // Lose parity shard 0
        let mut shards: Vec<Option<Vec<u8>>> = vec![None; 5];
        shards[0] = Some(data[0].clone());
        shards[1] = Some(data[1].clone());
        shards[2] = Some(data[2].clone());
        shards[3] = None; // lost parity
        shards[4] = Some(parity[1].clone());

        let shard_present = vec![true, true, true, false, true];
        rs.reconstruct(&mut shards, &shard_present).unwrap();

        assert_eq!(shards[3].as_ref().unwrap(), &parity[0]);
    }

    #[test]
    fn test_reconstruct_mixed_loss() {
        let rs = ReedSolomon::new(4, 3).unwrap();
        let data: Vec<Vec<u8>> = vec![
            vec![1, 2, 3, 4],
            vec![5, 6, 7, 8],
            vec![9, 10, 11, 12],
            vec![13, 14, 15, 16],
        ];
        let parity = rs.encode(&data).unwrap();

        // Lose data shard 0, parity shards 0 and 2
        let mut shards: Vec<Option<Vec<u8>>> = vec![None; 7];
        shards[0] = None; // lost data
        shards[1] = Some(data[1].clone());
        shards[2] = Some(data[2].clone());
        shards[3] = Some(data[3].clone());
        shards[4] = None; // lost parity
        shards[5] = Some(parity[1].clone());
        shards[6] = None; // lost parity

        let shard_present = vec![false, true, true, true, false, true, false];
        rs.reconstruct(&mut shards, &shard_present).unwrap();

        assert_eq!(shards[0].as_ref().unwrap(), &data[0]);
        assert_eq!(shards[4].as_ref().unwrap(), &parity[0]);
        assert_eq!(shards[6].as_ref().unwrap(), &parity[2]);
    }

    #[test]
    fn test_reconstruct_too_many_lost() {
        let rs = ReedSolomon::new(3, 2).unwrap();
        let data: Vec<Vec<u8>> = vec![vec![1, 2, 3], vec![4, 5, 6], vec![7, 8, 9]];
        let parity = rs.encode(&data).unwrap();

        // Lose 3 shards (more than parity_shards = 2)
        let mut shards: Vec<Option<Vec<u8>>> = vec![None; 5];
        shards[0] = None;
        shards[1] = Some(data[1].clone());
        shards[2] = None;
        shards[3] = None;
        shards[4] = Some(parity[1].clone());

        let shard_present = vec![false, true, false, false, true];
        assert!(rs.reconstruct(&mut shards, &shard_present).is_err());
    }

    #[test]
    fn test_reconstruct_wrong_shard_count() {
        let rs = ReedSolomon::new(3, 2).unwrap();
        let mut shards: Vec<Option<Vec<u8>>> = vec![None; 3];
        let shard_present = vec![true; 3];
        assert!(rs.reconstruct(&mut shards, &shard_present).is_err());
    }

    #[test]
    fn test_roundtrip_large_data() {
        let rs = ReedSolomon::new(5, 3).unwrap();
        let data: Vec<Vec<u8>> = (0..5)
            .map(|i| (0..100).map(|j| ((i * 100 + j) % 256) as u8).collect())
            .collect();
        let parity = rs.encode(&data).unwrap();

        // Lose 3 shards (the maximum)
        let mut shards: Vec<Option<Vec<u8>>> = vec![None; 8];
        shards[0] = None; // lost
        shards[1] = Some(data[1].clone());
        shards[2] = None; // lost
        shards[3] = Some(data[3].clone());
        shards[4] = None; // lost
        shards[5] = Some(parity[0].clone());
        shards[6] = Some(parity[1].clone());
        shards[7] = Some(parity[2].clone());

        let shard_present = vec![false, true, false, true, false, true, true, true];
        rs.reconstruct(&mut shards, &shard_present).unwrap();

        assert_eq!(shards[0].as_ref().unwrap(), &data[0]);
        assert_eq!(shards[2].as_ref().unwrap(), &data[2]);
        assert_eq!(shards[4].as_ref().unwrap(), &data[4]);
    }

    #[test]
    fn test_encode_zeros() {
        let rs = ReedSolomon::new(3, 2).unwrap();
        let data: Vec<Vec<u8>> = vec![vec![0, 0, 0], vec![0, 0, 0], vec![0, 0, 0]];
        let parity = rs.encode(&data).unwrap();
        assert_eq!(parity[0], vec![0, 0, 0]);
        assert_eq!(parity[1], vec![0, 0, 0]);
    }

    #[test]
    fn test_vandermonde_first_row_ones() {
        let gf = Gf256::new();
        let vand = vandermonde(5, 3, &gf);
        for j in 0..3 {
            assert_eq!(
                vand.get(0, j),
                1,
                "First row of Vandermonde should be all 1s"
            );
        }
    }
}
