//! Formally verified lattice proofs for lattice-guard.
//!
//! This crate contains Verus SMT proofs that the core algebraic structures
//! in lattice-guard satisfy their mathematical laws. These proofs are
//! machine-checked by the Z3 SMT solver via Verus.
//!
//! # Verified Properties
//!
//! ## CapabilityLevel (3-element total order: Never < LowRisk < Always)
//! - Meet (min) and Join (max) form a bounded distributive lattice
//! - All 7 lattice laws: commutativity, associativity, idempotence,
//!   absorption, distributivity, bounded (top/bottom identity)
//! - Partial order consistency: a ≤ b iff meet(a, b) = a
//!
//! ## CapabilityLattice (12-dimensional product lattice)
//! - Product of 12 CapabilityLevel dimensions
//! - Inherits all lattice laws from the component lattice
//! - Meet/join are element-wise min/max
//!
//! # Running Verification
//!
//! ```bash
//! .verus/verus-x86-macos/verus crates/lattice-guard-verified/src/lib.rs
//! ```

use vstd::prelude::*;

verus! {

// ============================================================================
// CapabilityLevel: 3-element total order {Never=0, LowRisk=1, Always=2}
// ============================================================================

/// Models lattice_guard::CapabilityLevel as a u8 in {0, 1, 2}.
/// Never=0, LowRisk=1, Always=2.
///
/// We use u8 rather than an enum because Verus's SMT encoding handles
/// integer arithmetic natively, making proofs more automated.
pub type CapLevel = u8;

/// Valid capability level: 0, 1, or 2.
pub open spec fn valid_cap(c: CapLevel) -> bool {
    c <= 2
}

/// Meet (greatest lower bound) = min.
pub open spec fn cap_meet(a: CapLevel, b: CapLevel) -> CapLevel {
    if a <= b { a } else { b }
}

/// Join (least upper bound) = max.
pub open spec fn cap_join(a: CapLevel, b: CapLevel) -> CapLevel {
    if a >= b { a } else { b }
}

/// Partial order: a ≤ b in the lattice.
pub open spec fn cap_leq(a: CapLevel, b: CapLevel) -> bool {
    a <= b
}

/// Top element (⊤) = Always = 2.
pub open spec fn cap_top() -> CapLevel { 2 }

/// Bottom element (⊥) = Never = 0.
pub open spec fn cap_bot() -> CapLevel { 0 }

// ============================================================================
// Lattice Law Proofs for CapabilityLevel
// ============================================================================

// --- Meet laws ---

/// Meet is commutative: meet(a, b) = meet(b, a)
proof fn proof_meet_commutative(a: CapLevel, b: CapLevel)
    requires
        valid_cap(a),
        valid_cap(b),
    ensures
        cap_meet(a, b) == cap_meet(b, a),
{
}

/// Meet is associative: meet(meet(a, b), c) = meet(a, meet(b, c))
proof fn proof_meet_associative(a: CapLevel, b: CapLevel, c: CapLevel)
    requires
        valid_cap(a),
        valid_cap(b),
        valid_cap(c),
    ensures
        cap_meet(cap_meet(a, b), c) == cap_meet(a, cap_meet(b, c)),
{
}

/// Meet is idempotent: meet(a, a) = a
proof fn proof_meet_idempotent(a: CapLevel)
    requires
        valid_cap(a),
    ensures
        cap_meet(a, a) == a,
{
}

// --- Join laws ---

/// Join is commutative: join(a, b) = join(b, a)
proof fn proof_join_commutative(a: CapLevel, b: CapLevel)
    requires
        valid_cap(a),
        valid_cap(b),
    ensures
        cap_join(a, b) == cap_join(b, a),
{
}

/// Join is associative: join(join(a, b), c) = join(a, join(b, c))
proof fn proof_join_associative(a: CapLevel, b: CapLevel, c: CapLevel)
    requires
        valid_cap(a),
        valid_cap(b),
        valid_cap(c),
    ensures
        cap_join(cap_join(a, b), c) == cap_join(a, cap_join(b, c)),
{
}

/// Join is idempotent: join(a, a) = a
proof fn proof_join_idempotent(a: CapLevel)
    requires
        valid_cap(a),
    ensures
        cap_join(a, a) == a,
{
}

// --- Absorption laws ---

/// Absorption: meet(a, join(a, b)) = a
proof fn proof_absorption_meet_join(a: CapLevel, b: CapLevel)
    requires
        valid_cap(a),
        valid_cap(b),
    ensures
        cap_meet(a, cap_join(a, b)) == a,
{
}

/// Absorption: join(a, meet(a, b)) = a
proof fn proof_absorption_join_meet(a: CapLevel, b: CapLevel)
    requires
        valid_cap(a),
        valid_cap(b),
    ensures
        cap_join(a, cap_meet(a, b)) == a,
{
}

// --- Bounded lattice laws ---

/// Top is identity for meet: meet(a, ⊤) = a
proof fn proof_meet_top_identity(a: CapLevel)
    requires
        valid_cap(a),
    ensures
        cap_meet(a, cap_top()) == a,
{
}

/// Bottom is identity for join: join(a, ⊥) = a
proof fn proof_join_bot_identity(a: CapLevel)
    requires
        valid_cap(a),
    ensures
        cap_join(a, cap_bot()) == a,
{
}

/// Bottom is annihilator for meet: meet(a, ⊥) = ⊥
proof fn proof_meet_bot_annihilator(a: CapLevel)
    requires
        valid_cap(a),
    ensures
        cap_meet(a, cap_bot()) == cap_bot(),
{
}

/// Top is annihilator for join: join(a, ⊤) = ⊤
proof fn proof_join_top_annihilator(a: CapLevel)
    requires
        valid_cap(a),
    ensures
        cap_join(a, cap_top()) == cap_top(),
{
}

// --- Distributivity ---

/// Meet distributes over join: meet(a, join(b, c)) = join(meet(a, b), meet(a, c))
proof fn proof_meet_distributes_over_join(a: CapLevel, b: CapLevel, c: CapLevel)
    requires
        valid_cap(a),
        valid_cap(b),
        valid_cap(c),
    ensures
        cap_meet(a, cap_join(b, c)) == cap_join(cap_meet(a, b), cap_meet(a, c)),
{
}

/// Join distributes over meet: join(a, meet(b, c)) = meet(join(a, b), join(a, c))
proof fn proof_join_distributes_over_meet(a: CapLevel, b: CapLevel, c: CapLevel)
    requires
        valid_cap(a),
        valid_cap(b),
        valid_cap(c),
    ensures
        cap_join(a, cap_meet(b, c)) == cap_meet(cap_join(a, b), cap_join(a, c)),
{
}

// --- Partial order consistency ---

/// The partial order is consistent with meet: a ≤ b iff meet(a, b) = a
proof fn proof_order_consistent_with_meet(a: CapLevel, b: CapLevel)
    requires
        valid_cap(a),
        valid_cap(b),
    ensures
        cap_leq(a, b) <==> cap_meet(a, b) == a,
{
}

/// The partial order is consistent with join: a ≤ b iff join(a, b) = b
proof fn proof_order_consistent_with_join(a: CapLevel, b: CapLevel)
    requires
        valid_cap(a),
        valid_cap(b),
    ensures
        cap_leq(a, b) <==> cap_join(a, b) == b,
{
}

/// The order is reflexive: a ≤ a
proof fn proof_order_reflexive(a: CapLevel)
    requires
        valid_cap(a),
    ensures
        cap_leq(a, a),
{
}

/// The order is antisymmetric: a ≤ b ∧ b ≤ a ⟹ a = b
proof fn proof_order_antisymmetric(a: CapLevel, b: CapLevel)
    requires
        valid_cap(a),
        valid_cap(b),
        cap_leq(a, b),
        cap_leq(b, a),
    ensures
        a == b,
{
}

/// The order is transitive: a ≤ b ∧ b ≤ c ⟹ a ≤ c
proof fn proof_order_transitive(a: CapLevel, b: CapLevel, c: CapLevel)
    requires
        valid_cap(a),
        valid_cap(b),
        valid_cap(c),
        cap_leq(a, b),
        cap_leq(b, c),
    ensures
        cap_leq(a, c),
{
}

/// The order is total: a ≤ b ∨ b ≤ a
proof fn proof_order_total(a: CapLevel, b: CapLevel)
    requires
        valid_cap(a),
        valid_cap(b),
    ensures
        cap_leq(a, b) || cap_leq(b, a),
{
}

// ============================================================================
// CapabilityLattice: 12-dimensional product lattice
// ============================================================================

/// Models lattice_guard::CapabilityLattice as a 12-tuple of CapLevels.
///
/// Fields (in order): read_files, write_files, edit_files, run_bash,
/// glob_search, grep_search, web_search, web_fetch, git_commit,
/// git_push, create_pr, manage_pods.
pub struct CapLattice {
    pub f0: CapLevel,  // read_files
    pub f1: CapLevel,  // write_files
    pub f2: CapLevel,  // edit_files
    pub f3: CapLevel,  // run_bash
    pub f4: CapLevel,  // glob_search
    pub f5: CapLevel,  // grep_search
    pub f6: CapLevel,  // web_search
    pub f7: CapLevel,  // web_fetch
    pub f8: CapLevel,  // git_commit
    pub f9: CapLevel,  // git_push
    pub f10: CapLevel, // create_pr
    pub f11: CapLevel, // manage_pods
}

/// A CapLattice is valid when all 12 components are valid CapLevels.
pub open spec fn valid_lattice(l: CapLattice) -> bool {
    valid_cap(l.f0) && valid_cap(l.f1) && valid_cap(l.f2) && valid_cap(l.f3)
    && valid_cap(l.f4) && valid_cap(l.f5) && valid_cap(l.f6) && valid_cap(l.f7)
    && valid_cap(l.f8) && valid_cap(l.f9) && valid_cap(l.f10) && valid_cap(l.f11)
}

/// Element-wise meet of two CapLattices.
pub open spec fn lattice_meet(a: CapLattice, b: CapLattice) -> CapLattice {
    CapLattice {
        f0: cap_meet(a.f0, b.f0),
        f1: cap_meet(a.f1, b.f1),
        f2: cap_meet(a.f2, b.f2),
        f3: cap_meet(a.f3, b.f3),
        f4: cap_meet(a.f4, b.f4),
        f5: cap_meet(a.f5, b.f5),
        f6: cap_meet(a.f6, b.f6),
        f7: cap_meet(a.f7, b.f7),
        f8: cap_meet(a.f8, b.f8),
        f9: cap_meet(a.f9, b.f9),
        f10: cap_meet(a.f10, b.f10),
        f11: cap_meet(a.f11, b.f11),
    }
}

/// Element-wise join of two CapLattices.
pub open spec fn lattice_join(a: CapLattice, b: CapLattice) -> CapLattice {
    CapLattice {
        f0: cap_join(a.f0, b.f0),
        f1: cap_join(a.f1, b.f1),
        f2: cap_join(a.f2, b.f2),
        f3: cap_join(a.f3, b.f3),
        f4: cap_join(a.f4, b.f4),
        f5: cap_join(a.f5, b.f5),
        f6: cap_join(a.f6, b.f6),
        f7: cap_join(a.f7, b.f7),
        f8: cap_join(a.f8, b.f8),
        f9: cap_join(a.f9, b.f9),
        f10: cap_join(a.f10, b.f10),
        f11: cap_join(a.f11, b.f11),
    }
}

/// Element-wise partial order on CapLattices.
pub open spec fn lattice_leq(a: CapLattice, b: CapLattice) -> bool {
    cap_leq(a.f0, b.f0) && cap_leq(a.f1, b.f1) && cap_leq(a.f2, b.f2)
    && cap_leq(a.f3, b.f3) && cap_leq(a.f4, b.f4) && cap_leq(a.f5, b.f5)
    && cap_leq(a.f6, b.f6) && cap_leq(a.f7, b.f7) && cap_leq(a.f8, b.f8)
    && cap_leq(a.f9, b.f9) && cap_leq(a.f10, b.f10) && cap_leq(a.f11, b.f11)
}

/// Top element: all capabilities at Always.
pub open spec fn lattice_top() -> CapLattice {
    CapLattice {
        f0: cap_top(), f1: cap_top(), f2: cap_top(), f3: cap_top(),
        f4: cap_top(), f5: cap_top(), f6: cap_top(), f7: cap_top(),
        f8: cap_top(), f9: cap_top(), f10: cap_top(), f11: cap_top(),
    }
}

/// Bottom element: all capabilities at Never.
pub open spec fn lattice_bot() -> CapLattice {
    CapLattice {
        f0: cap_bot(), f1: cap_bot(), f2: cap_bot(), f3: cap_bot(),
        f4: cap_bot(), f5: cap_bot(), f6: cap_bot(), f7: cap_bot(),
        f8: cap_bot(), f9: cap_bot(), f10: cap_bot(), f11: cap_bot(),
    }
}

// ============================================================================
// Product Lattice Law Proofs
// ============================================================================

/// Product meet is commutative.
proof fn proof_lattice_meet_commutative(a: CapLattice, b: CapLattice)
    requires
        valid_lattice(a),
        valid_lattice(b),
    ensures
        lattice_meet(a, b) == lattice_meet(b, a),
{
}

/// Product meet is associative.
proof fn proof_lattice_meet_associative(a: CapLattice, b: CapLattice, c: CapLattice)
    requires
        valid_lattice(a),
        valid_lattice(b),
        valid_lattice(c),
    ensures
        lattice_meet(lattice_meet(a, b), c) == lattice_meet(a, lattice_meet(b, c)),
{
}

/// Product meet is idempotent.
proof fn proof_lattice_meet_idempotent(a: CapLattice)
    requires
        valid_lattice(a),
    ensures
        lattice_meet(a, a) == a,
{
}

/// Product join is commutative.
proof fn proof_lattice_join_commutative(a: CapLattice, b: CapLattice)
    requires
        valid_lattice(a),
        valid_lattice(b),
    ensures
        lattice_join(a, b) == lattice_join(b, a),
{
}

/// Product join is associative.
proof fn proof_lattice_join_associative(a: CapLattice, b: CapLattice, c: CapLattice)
    requires
        valid_lattice(a),
        valid_lattice(b),
        valid_lattice(c),
    ensures
        lattice_join(lattice_join(a, b), c) == lattice_join(a, lattice_join(b, c)),
{
}

/// Product join is idempotent.
proof fn proof_lattice_join_idempotent(a: CapLattice)
    requires
        valid_lattice(a),
    ensures
        lattice_join(a, a) == a,
{
}

/// Product absorption: meet(a, join(a, b)) = a
proof fn proof_lattice_absorption_meet_join(a: CapLattice, b: CapLattice)
    requires
        valid_lattice(a),
        valid_lattice(b),
    ensures
        lattice_meet(a, lattice_join(a, b)) == a,
{
}

/// Product absorption: join(a, meet(a, b)) = a
proof fn proof_lattice_absorption_join_meet(a: CapLattice, b: CapLattice)
    requires
        valid_lattice(a),
        valid_lattice(b),
    ensures
        lattice_join(a, lattice_meet(a, b)) == a,
{
}

/// Product meet distributes over join.
///
/// Proof strategy: invoke the per-component distributivity lemma for each
/// of the 12 dimensions, then Z3 can unify the struct equality.
proof fn proof_lattice_distributive(a: CapLattice, b: CapLattice, c: CapLattice)
    requires
        valid_lattice(a),
        valid_lattice(b),
        valid_lattice(c),
    ensures
        lattice_meet(a, lattice_join(b, c))
            == lattice_join(lattice_meet(a, b), lattice_meet(a, c)),
{
    proof_meet_distributes_over_join(a.f0, b.f0, c.f0);
    proof_meet_distributes_over_join(a.f1, b.f1, c.f1);
    proof_meet_distributes_over_join(a.f2, b.f2, c.f2);
    proof_meet_distributes_over_join(a.f3, b.f3, c.f3);
    proof_meet_distributes_over_join(a.f4, b.f4, c.f4);
    proof_meet_distributes_over_join(a.f5, b.f5, c.f5);
    proof_meet_distributes_over_join(a.f6, b.f6, c.f6);
    proof_meet_distributes_over_join(a.f7, b.f7, c.f7);
    proof_meet_distributes_over_join(a.f8, b.f8, c.f8);
    proof_meet_distributes_over_join(a.f9, b.f9, c.f9);
    proof_meet_distributes_over_join(a.f10, b.f10, c.f10);
    proof_meet_distributes_over_join(a.f11, b.f11, c.f11);
}

/// Top is identity for product meet.
proof fn proof_lattice_meet_top(a: CapLattice)
    requires
        valid_lattice(a),
    ensures
        lattice_meet(a, lattice_top()) == a,
{
}

/// Bottom is identity for product join.
proof fn proof_lattice_join_bot(a: CapLattice)
    requires
        valid_lattice(a),
    ensures
        lattice_join(a, lattice_bot()) == a,
{
}

/// Product order is consistent with meet: a ≤ b iff meet(a, b) = a
proof fn proof_lattice_order_consistent(a: CapLattice, b: CapLattice)
    requires
        valid_lattice(a),
        valid_lattice(b),
    ensures
        lattice_leq(a, b) <==> lattice_meet(a, b) == a,
{
}

// ============================================================================
// Trifecta Detection
// ============================================================================

/// Models the lethal trifecta risk assessment.
///
/// The trifecta is complete when ALL THREE are present at ≥ LowRisk:
/// 1. Private data access (read_files OR glob_search OR grep_search)
/// 2. Untrusted content (web_fetch OR web_search)
/// 3. Exfiltration vector (git_push OR create_pr OR run_bash)
pub open spec fn has_private_access(l: CapLattice) -> bool {
    l.f0 >= 1 || l.f4 >= 1 || l.f5 >= 1  // read_files, glob_search, grep_search
}

pub open spec fn has_untrusted_content(l: CapLattice) -> bool {
    l.f6 >= 1 || l.f7 >= 1  // web_search, web_fetch
}

pub open spec fn has_exfiltration(l: CapLattice) -> bool {
    l.f3 >= 1 || l.f9 >= 1 || l.f10 >= 1  // run_bash, git_push, create_pr
}

pub open spec fn is_trifecta_complete(l: CapLattice) -> bool {
    has_private_access(l) && has_untrusted_content(l) && has_exfiltration(l)
}

/// Meet can only decrease or maintain trifecta risk (monotonicity).
///
/// If neither a nor b has the trifecta, their meet doesn't either.
/// This is because meet takes the min of each component, so if a component
/// is Never in either input, it's Never in the output.
proof fn proof_trifecta_meet_monotone(a: CapLattice, b: CapLattice)
    requires
        valid_lattice(a),
        valid_lattice(b),
        !is_trifecta_complete(a),
    ensures
        !is_trifecta_complete(lattice_meet(a, b)),
{
}

/// The nucleus (normalize) is deflationary: lattice_leq(meet(a, b), a).
/// Meet of a with anything is ≤ a.
proof fn proof_meet_deflationary(a: CapLattice, b: CapLattice)
    requires
        valid_lattice(a),
        valid_lattice(b),
    ensures
        lattice_leq(lattice_meet(a, b), a),
{
}

/// Meet preserves the valid_lattice invariant.
proof fn proof_meet_preserves_validity(a: CapLattice, b: CapLattice)
    requires
        valid_lattice(a),
        valid_lattice(b),
    ensures
        valid_lattice(lattice_meet(a, b)),
{
}

/// Join preserves the valid_lattice invariant.
proof fn proof_join_preserves_validity(a: CapLattice, b: CapLattice)
    requires
        valid_lattice(a),
        valid_lattice(b),
    ensures
        valid_lattice(lattice_join(a, b)),
{
}

fn main() {}

} // verus!
