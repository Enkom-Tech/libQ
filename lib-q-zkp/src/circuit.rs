//! Circuit builder for arithmetic constraints
//!
//! This module provides a circuit abstraction for building arithmetic constraints
//! that can be compiled into AIR (Algebraic Intermediate Representation) for STARK proofs.

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;

use lib_q_stark_air::{
    Air,
    AirBuilder,
    BaseAir,
    WindowAccess,
};
use lib_q_stark_field::Field;

/// A wire in the circuit, representing a field element
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Wire {
    /// The index of the wire in the witness vector
    pub index: usize,
}

impl Wire {
    /// Create a new wire with the given index
    pub fn new(index: usize) -> Self {
        Self { index }
    }
}

/// A constraint in the circuit
#[derive(Debug, Clone)]
pub enum Constraint<F: Field> {
    /// Assert that a wire equals zero: `wire == 0`
    AssertZero(Wire),
    /// Assert that two wires are equal: `left == right`
    AssertEqual(Wire, Wire),
    /// Assert that a wire equals a constant: `wire == constant`
    AssertConstant(Wire, F),
    /// Assert that a wire equals the sum of two wires: `wire == left + right`
    AssertAdd(Wire, Wire, Wire),
    /// Assert that a wire equals the product of two wires: `wire == left * right`
    AssertMul(Wire, Wire, Wire),
}

/// An arithmetic circuit containing constraints and metadata
#[derive(Debug, Clone)]
pub struct ArithmeticCircuit<F: Field> {
    /// The constraints in the circuit
    pub constraints: Vec<Constraint<F>>,
    /// The number of witness wires (excluding public inputs)
    pub witness_size: usize,
    /// The number of public input wires
    pub public_input_size: usize,
}

impl<F: Field> ArithmeticCircuit<F> {
    /// Create a new empty circuit
    pub fn new(witness_size: usize, public_input_size: usize) -> Self {
        Self {
            constraints: Vec::new(),
            witness_size,
            public_input_size,
        }
    }

    /// Get the total number of wires (witness + public inputs)
    pub fn total_wires(&self) -> usize {
        self.witness_size + self.public_input_size
    }

    /// Add a constraint to the circuit
    pub fn add_constraint(&mut self, constraint: Constraint<F>) {
        self.constraints.push(constraint);
    }
}

/// Builder for constructing arithmetic circuits
pub struct CircuitBuilder<F: Field> {
    circuit: ArithmeticCircuit<F>,
    next_wire: usize,
}

impl<F: Field> CircuitBuilder<F> {
    /// Create a new circuit builder
    ///
    /// # Arguments
    ///
    /// * `witness_size` - Number of witness wires (private inputs)
    /// * `public_input_size` - Number of public input wires
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use lib_q_zkp::circuit::CircuitBuilder;
    /// use lib_q_stark_field::extension::Complex;
    /// use lib_q_stark_mersenne31::Mersenne31;
    ///
    /// type Val = Complex<Mersenne31>;
    ///
    /// let mut builder = CircuitBuilder::<Val>::new(2, 1);
    /// let a = builder.wire(0);  // witness wire 0
    /// let b = builder.wire(1);  // witness wire 1
    /// let sum = builder.add(a, b);
    /// builder.assert_zero(sum);
    /// let circuit = builder.build();
    /// ```
    pub fn new(witness_size: usize, public_input_size: usize) -> Self {
        Self {
            circuit: ArithmeticCircuit::new(witness_size, public_input_size),
            next_wire: witness_size + public_input_size,
        }
    }

    /// Allocate a new intermediate wire
    pub fn alloc_wire(&mut self) -> Wire {
        let wire = Wire::new(self.next_wire);
        self.next_wire += 1;
        wire
    }

    /// Get a wire by index (for public inputs and witness)
    pub fn wire(&self, index: usize) -> Wire {
        Wire::new(index)
    }

    /// Assert that a wire equals zero
    pub fn assert_zero(&mut self, wire: Wire) {
        self.circuit.add_constraint(Constraint::AssertZero(wire));
    }

    /// Assert that two wires are equal
    pub fn assert_eq(&mut self, left: Wire, right: Wire) {
        self.circuit
            .add_constraint(Constraint::AssertEqual(left, right));
    }

    /// Assert that a wire equals a constant
    pub fn assert_constant(&mut self, wire: Wire, constant: F) {
        self.circuit
            .add_constraint(Constraint::AssertConstant(wire, constant));
    }

    /// Add two wires and return the result wire
    pub fn add(&mut self, left: Wire, right: Wire) -> Wire {
        let result = self.alloc_wire();
        self.circuit
            .add_constraint(Constraint::AssertAdd(result, left, right));
        result
    }

    /// Multiply two wires and return the result wire
    pub fn mul(&mut self, left: Wire, right: Wire) -> Wire {
        let result = self.alloc_wire();
        self.circuit
            .add_constraint(Constraint::AssertMul(result, left, right));
        result
    }

    /// Build the circuit
    pub fn build(self) -> ArithmeticCircuit<F> {
        self.circuit
    }
}

/// AIR implementation for an arithmetic circuit
///
/// This converts a circuit into an AIR that can be used with STARK proving.
/// The trace represents all wire values, with one row containing all wire values.
pub struct CircuitAir<F: Field> {
    circuit: ArithmeticCircuit<F>,
}

impl<F: Field> CircuitAir<F> {
    /// Create a new CircuitAir from an ArithmeticCircuit
    pub fn new(circuit: ArithmeticCircuit<F>) -> Self {
        Self { circuit }
    }

    /// Get a reference to the underlying circuit
    pub fn circuit(&self) -> &ArithmeticCircuit<F> {
        &self.circuit
    }

    /// Generate an execution trace from witness values
    ///
    /// The witness values should include all wire values in the circuit.
    /// Wire indices 0..witness_size are witness wires,
    /// indices witness_size..witness_size+public_input_size are public inputs,
    /// and remaining indices are intermediate wires.
    ///
    /// # Arguments
    ///
    /// * `witness` - Private witness values (witness wires)
    /// * `public` - Public input values
    ///
    /// # Returns
    ///
    /// A RowMajorMatrix containing the trace, or an error if validation fails
    pub fn generate_trace(
        &self,
        witness: &[F],
        public: &[F],
    ) -> Result<lib_q_stark_matrix::dense::RowMajorMatrix<F>, lib_q_core::Error> {
        use lib_q_stark_matrix::dense::RowMajorMatrix;

        // Validate input sizes
        if witness.len() != self.circuit.witness_size {
            return Err(lib_q_core::Error::InvalidState {
                operation: "CircuitAir::generate_trace".into(),
                reason: alloc::format!(
                    "Witness size mismatch: expected {}, got {}",
                    self.circuit.witness_size,
                    witness.len()
                ),
            });
        }

        if public.len() != self.circuit.public_input_size {
            return Err(lib_q_core::Error::InvalidState {
                operation: "CircuitAir::generate_trace".into(),
                reason: alloc::format!(
                    "Public input size mismatch: expected {}, got {}",
                    self.circuit.public_input_size,
                    public.len()
                ),
            });
        }

        let width = self.width();

        // Allocate trace for a single row (power of 2)
        let mut trace_values = F::zero_vec(width);

        // Fill witness wires
        for (i, val) in witness.iter().enumerate() {
            if i < width {
                trace_values[i] = *val;
            }
        }

        // Fill public input wires
        for (i, val) in public.iter().enumerate() {
            let idx = self.circuit.witness_size + i;
            if idx < width {
                trace_values[idx] = *val;
            }
        }

        // Compute intermediate wire values by evaluating constraints
        for constraint in &self.circuit.constraints {
            match constraint {
                Constraint::AssertAdd(out, l, r)
                    if out.index < width && l.index < width && r.index < width =>
                {
                    trace_values[out.index] = trace_values[l.index] + trace_values[r.index];
                }
                Constraint::AssertMul(out, l, r)
                    if out.index < width && l.index < width && r.index < width =>
                {
                    trace_values[out.index] = trace_values[l.index] * trace_values[r.index];
                }
                // Other constraints don't compute new values
                _ => {}
            }
        }

        // Pad to at least MIN_TRACE_ROWS so FRI has sufficient two-adic height (degree >= 1)
        const MIN_TRACE_ROWS: usize = 64;
        if MIN_TRACE_ROWS > 1 {
            let mut padded = trace_values.clone();
            for _ in 1..MIN_TRACE_ROWS {
                padded.extend_from_slice(&trace_values);
            }
            Ok(RowMajorMatrix::new(padded, width))
        } else {
            Ok(RowMajorMatrix::new(trace_values, width))
        }
    }
}

impl<F: Field> BaseAir<F> for CircuitAir<F> {
    fn width(&self) -> usize {
        // The width is the total number of wires (witness + public inputs + intermediate wires)
        // We need to compute this from the constraints
        let max_wire = self
            .circuit
            .constraints
            .iter()
            .flat_map(|c| match c {
                Constraint::AssertZero(w) => vec![w.index],
                Constraint::AssertEqual(l, r) => vec![l.index, r.index],
                Constraint::AssertConstant(w, _) => vec![w.index],
                Constraint::AssertAdd(r, l, r2) => vec![r.index, l.index, r2.index],
                Constraint::AssertMul(r, l, r2) => vec![r.index, l.index, r2.index],
            })
            .max()
            .unwrap_or(0);
        (max_wire + 1).max(self.circuit.total_wires())
    }
}

impl<F: Field, AB: AirBuilder<F = F>> Air<AB> for CircuitAir<F> {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let row = main.current_slice();

        // Evaluate each constraint in the circuit
        for constraint in &self.circuit.constraints {
            match constraint {
                Constraint::AssertZero(w) => {
                    // Constraint: wire[w.index] == 0
                    if w.index < row.len() {
                        builder.assert_zero(row[w.index].clone());
                    }
                }
                Constraint::AssertEqual(l, r) => {
                    // Constraint: wire[l.index] == wire[r.index]
                    if l.index < row.len() && r.index < row.len() {
                        builder.assert_eq(row[l.index].clone(), row[r.index].clone());
                    }
                }
                Constraint::AssertConstant(w, c) => {
                    // Constraint: wire[w.index] == constant
                    if w.index < row.len() {
                        builder.assert_eq(row[w.index].clone(), *c);
                    }
                }
                Constraint::AssertAdd(out, l, r) => {
                    // Constraint: wire[out.index] == wire[l.index] + wire[r.index]
                    if out.index < row.len() && l.index < row.len() && r.index < row.len() {
                        let sum = row[l.index].clone() + row[r.index].clone();
                        builder.assert_eq(row[out.index].clone(), sum);
                    }
                }
                Constraint::AssertMul(out, l, r) => {
                    // Constraint: wire[out.index] == wire[l.index] * wire[r.index]
                    if out.index < row.len() && l.index < row.len() && r.index < row.len() {
                        let product = row[l.index].clone() * row[r.index].clone();
                        builder.assert_eq(row[out.index].clone(), product);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use lib_q_stark_air::BaseAir;
    use lib_q_stark_field::PrimeCharacteristicRing;
    use lib_q_stark_field::extension::Complex;
    use lib_q_stark_mersenne31::Mersenne31;

    use super::*;

    type TestField = Complex<Mersenne31>;

    #[test]
    fn test_circuit_builder_new() {
        let builder = CircuitBuilder::<TestField>::new(5, 2);
        let circuit = builder.build();
        assert_eq!(circuit.witness_size, 5);
        assert_eq!(circuit.public_input_size, 2);
        assert_eq!(circuit.total_wires(), 7);
    }

    #[test]
    fn test_circuit_builder_alloc_wire() {
        let mut builder = CircuitBuilder::<TestField>::new(3, 2);
        let wire1 = builder.alloc_wire();
        let wire2 = builder.alloc_wire();
        assert_eq!(wire1.index, 5); // 3 witness + 2 public = 5
        assert_eq!(wire2.index, 6);
    }

    #[test]
    fn test_circuit_builder_constraints() {
        let mut builder = CircuitBuilder::<TestField>::new(2, 1);
        let w0 = builder.wire(0);
        let w1 = builder.wire(1);
        let w2 = builder.wire(2);

        builder.assert_zero(w0);
        builder.assert_eq(w1, w2);
        builder.assert_constant(w0, <TestField as PrimeCharacteristicRing>::ONE);

        let circuit = builder.build();
        assert_eq!(circuit.constraints.len(), 3);
    }

    #[test]
    fn test_circuit_builder_add_mul() {
        let mut builder = CircuitBuilder::<TestField>::new(2, 1);
        let a = builder.wire(0);
        let b = builder.wire(1);
        let sum = builder.add(a, b);
        let product = builder.mul(a, b);

        assert!(sum.index >= 3);
        assert!(product.index >= 3);
        assert!(product.index > sum.index);

        let circuit = builder.build();
        assert_eq!(circuit.constraints.len(), 2);
    }

    #[test]
    fn test_arithmetic_circuit() {
        let mut circuit = ArithmeticCircuit::<TestField>::new(3, 2);
        circuit.add_constraint(Constraint::AssertZero(Wire::new(0)));
        circuit.add_constraint(Constraint::AssertEqual(Wire::new(1), Wire::new(2)));

        assert_eq!(circuit.constraints.len(), 2);
        assert_eq!(circuit.total_wires(), 5);
    }

    #[test]
    fn test_circuit_air_width() {
        let mut circuit = ArithmeticCircuit::<TestField>::new(2, 1);
        circuit.add_constraint(Constraint::AssertZero(Wire::new(0)));
        circuit.add_constraint(Constraint::AssertEqual(Wire::new(1), Wire::new(2)));

        let air = CircuitAir::new(circuit);
        assert!(BaseAir::<TestField>::width(&air) >= 3); // At least total_wires
    }
}
