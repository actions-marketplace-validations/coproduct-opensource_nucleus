//! Parameterized constraint system for dangerous taint combinations.
//!
//! The lethal trifecta (PrivateData + UntrustedContent + ExfilVector) is the
//! first and permanent constraint. This module generalizes the concept to
//! arbitrary dangerous combinations of core and extension taint labels.
//!
//! ## Mathematical Structure
//!
//! Each `DangerousCombo` is a deflationary nucleus on the permission lattice:
//! it only adds obligations, never removes them. The `ConstraintNucleus`
//! composes multiple combos via fixed-point iteration — the result is itself
//! a nucleus (composition of deflationary endomorphisms is deflationary).
//!
//! ## Proof Obligations for New Combos
//!
//! When adding a new `DangerousCombo`, the implementor must demonstrate:
//! 1. The combo's nucleus is deflationary (only adds obligations)
//! 2. It composes with the trifecta via the fixed-point iteration
//! 3. Property tests pass for the combo (template provided in tests)

use std::collections::BTreeSet;

use crate::capability::{Obligations, Operation, TrifectaRisk};
use crate::guard::{ExtensionTaintLabel, TaintLabel, TaintSet};

/// A dangerous combination of taint labels.
///
/// When all `required_core_labels` AND `required_ext_labels` are present in
/// a session's taint set, the `mitigation` obligations are imposed.
///
/// The trifecta is combo #0, always present, CANNOT be removed.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DangerousCombo {
    /// Human-readable name for this combination.
    pub name: String,
    /// Core taint labels required to trigger this combo.
    pub required_core_labels: BTreeSet<CoreTaintRequirement>,
    /// Extension taint labels required to trigger this combo.
    pub required_ext_labels: BTreeSet<ExtensionTaintLabel>,
    /// Obligations added when this combo is triggered.
    pub mitigation: Obligations,
    /// Risk grade when triggered.
    pub risk_grade: TrifectaRisk,
}

/// Core taint label requirements, mapping to the 3 verified labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum CoreTaintRequirement {
    /// Requires PrivateData taint.
    PrivateData,
    /// Requires UntrustedContent taint.
    UntrustedContent,
    /// Requires ExfilVector taint.
    ExfilVector,
}

impl CoreTaintRequirement {
    /// Convert to the corresponding TaintLabel.
    pub fn to_label(self) -> TaintLabel {
        match self {
            CoreTaintRequirement::PrivateData => TaintLabel::PrivateData,
            CoreTaintRequirement::UntrustedContent => TaintLabel::UntrustedContent,
            CoreTaintRequirement::ExfilVector => TaintLabel::ExfilVector,
        }
    }
}

impl DangerousCombo {
    /// Check if this combo is triggered by the given taint set.
    pub fn is_triggered(&self, taint: &TaintSet) -> bool {
        let core_met = self
            .required_core_labels
            .iter()
            .all(|req| taint.contains(req.to_label()));
        #[cfg(not(kani))]
        let ext_met = self
            .required_ext_labels
            .iter()
            .all(|label| taint.contains_extension(label));
        #[cfg(kani)]
        let ext_met = true;
        core_met && ext_met
    }

    /// The canonical trifecta combo. Always slot 0 in `ConstraintNucleus`.
    pub fn trifecta() -> Self {
        let mut required_core = BTreeSet::new();
        required_core.insert(CoreTaintRequirement::PrivateData);
        required_core.insert(CoreTaintRequirement::UntrustedContent);
        required_core.insert(CoreTaintRequirement::ExfilVector);

        let mut mitigation = Obligations::for_operation(Operation::GitPush);
        mitigation.insert(Operation::CreatePr);
        mitigation.insert(Operation::RunBash);

        Self {
            name: "lethal-trifecta".to_string(),
            required_core_labels: required_core,
            required_ext_labels: BTreeSet::new(),
            mitigation,
            risk_grade: TrifectaRisk::Complete,
        }
    }
}

/// The constraint nucleus: trifecta + additional dangerous combos.
///
/// The trifecta is always slot 0 and cannot be removed. Additional combos
/// are applied in order after the trifecta. Each combo is deflationary:
/// it only adds obligations, never removes them.
#[derive(Debug, Clone)]
pub struct ConstraintNucleus {
    /// Slot 0: the trifecta. Always present. Verified.
    trifecta: DangerousCombo,
    /// Additional dangerous combinations (tested, not verified).
    additional: Vec<DangerousCombo>,
}

impl Default for ConstraintNucleus {
    fn default() -> Self {
        Self {
            trifecta: DangerousCombo::trifecta(),
            additional: Vec::new(),
        }
    }
}

impl ConstraintNucleus {
    /// Create a new constraint nucleus with only the trifecta.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an additional dangerous combination.
    ///
    /// Returns `&mut Self` for chaining.
    pub fn with_combo(mut self, combo: DangerousCombo) -> Self {
        self.additional.push(combo);
        self
    }

    /// Add an additional dangerous combination by reference.
    pub fn add_combo(&mut self, combo: DangerousCombo) {
        self.additional.push(combo);
    }

    /// Apply all constraints to the given taint set. Returns accumulated obligations.
    ///
    /// Trifecta first, then additional combos. Each is deflationary:
    /// only adds obligations, never removes.
    pub fn apply(&self, taint: &TaintSet) -> Obligations {
        let mut obligations = Obligations::default();

        // Slot 0: the trifecta (always)
        if self.trifecta.is_triggered(taint) {
            obligations = obligations.union(&self.trifecta.mitigation);
        }

        // Additional combos
        for combo in &self.additional {
            if combo.is_triggered(taint) {
                obligations = obligations.union(&combo.mitigation);
            }
        }

        obligations
    }

    /// Return a reference to the trifecta combo.
    pub fn trifecta(&self) -> &DangerousCombo {
        &self.trifecta
    }

    /// Return all additional combos.
    pub fn additional(&self) -> &[DangerousCombo] {
        &self.additional
    }

    /// Total number of constraints (trifecta + additional).
    pub fn len(&self) -> usize {
        1 + self.additional.len()
    }

    /// Always false — the trifecta is always present.
    pub fn is_empty(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trifecta_combo_triggered() {
        let combo = DangerousCombo::trifecta();
        let full = TaintSet::singleton(TaintLabel::PrivateData)
            .union(&TaintSet::singleton(TaintLabel::UntrustedContent))
            .union(&TaintSet::singleton(TaintLabel::ExfilVector));
        assert!(combo.is_triggered(&full));
    }

    #[test]
    fn test_trifecta_combo_not_triggered_partial() {
        let combo = DangerousCombo::trifecta();
        let partial = TaintSet::singleton(TaintLabel::PrivateData)
            .union(&TaintSet::singleton(TaintLabel::UntrustedContent));
        assert!(!combo.is_triggered(&partial));
    }

    #[test]
    fn test_trifecta_combo_not_triggered_empty() {
        let combo = DangerousCombo::trifecta();
        assert!(!combo.is_triggered(&TaintSet::empty()));
    }

    #[test]
    fn test_extension_combo_triggered() {
        let mut required_ext = BTreeSet::new();
        required_ext.insert(ExtensionTaintLabel::new("code_execution"));

        let combo = DangerousCombo {
            name: "code-exec-with-private-data".to_string(),
            required_core_labels: {
                let mut s = BTreeSet::new();
                s.insert(CoreTaintRequirement::PrivateData);
                s
            },
            required_ext_labels: required_ext,
            mitigation: Obligations::for_operation(Operation::RunBash),
            risk_grade: TrifectaRisk::Medium,
        };

        let taint = TaintSet::singleton(TaintLabel::PrivateData).union(
            &TaintSet::extension_singleton(ExtensionTaintLabel::new("code_execution")),
        );
        assert!(combo.is_triggered(&taint));
    }

    #[test]
    fn test_extension_combo_not_triggered_missing_ext() {
        let mut required_ext = BTreeSet::new();
        required_ext.insert(ExtensionTaintLabel::new("code_execution"));

        let combo = DangerousCombo {
            name: "code-exec-with-private-data".to_string(),
            required_core_labels: {
                let mut s = BTreeSet::new();
                s.insert(CoreTaintRequirement::PrivateData);
                s
            },
            required_ext_labels: required_ext,
            mitigation: Obligations::for_operation(Operation::RunBash),
            risk_grade: TrifectaRisk::Medium,
        };

        // Has core label but missing extension label
        let taint = TaintSet::singleton(TaintLabel::PrivateData);
        assert!(!combo.is_triggered(&taint));
    }

    #[test]
    fn test_constraint_nucleus_default_has_trifecta() {
        let nucleus = ConstraintNucleus::new();
        assert_eq!(nucleus.len(), 1);
        assert!(!nucleus.is_empty());
        assert_eq!(nucleus.trifecta().name, "lethal-trifecta");
    }

    #[test]
    fn test_constraint_nucleus_apply_trifecta() {
        let nucleus = ConstraintNucleus::new();
        let full = TaintSet::singleton(TaintLabel::PrivateData)
            .union(&TaintSet::singleton(TaintLabel::UntrustedContent))
            .union(&TaintSet::singleton(TaintLabel::ExfilVector));

        let obligations = nucleus.apply(&full);
        assert!(obligations.requires(Operation::GitPush));
        assert!(obligations.requires(Operation::CreatePr));
        assert!(obligations.requires(Operation::RunBash));
    }

    #[test]
    fn test_constraint_nucleus_apply_no_taint() {
        let nucleus = ConstraintNucleus::new();
        let obligations = nucleus.apply(&TaintSet::empty());
        assert!(obligations.is_empty());
    }

    #[test]
    fn test_constraint_nucleus_with_additional_combo() {
        let ext_combo = DangerousCombo {
            name: "data-plus-exec".to_string(),
            required_core_labels: {
                let mut s = BTreeSet::new();
                s.insert(CoreTaintRequirement::PrivateData);
                s
            },
            required_ext_labels: {
                let mut s = BTreeSet::new();
                s.insert(ExtensionTaintLabel::new("code_execution"));
                s
            },
            mitigation: Obligations::for_operation(Operation::RunBash),
            risk_grade: TrifectaRisk::Medium,
        };

        let nucleus = ConstraintNucleus::new().with_combo(ext_combo);
        assert_eq!(nucleus.len(), 2);

        // Trigger only the extension combo, not the trifecta
        let taint = TaintSet::singleton(TaintLabel::PrivateData).union(
            &TaintSet::extension_singleton(ExtensionTaintLabel::new("code_execution")),
        );

        let obligations = nucleus.apply(&taint);
        assert!(obligations.requires(Operation::RunBash));
        // GitPush NOT required because trifecta wasn't triggered
        assert!(!obligations.requires(Operation::GitPush));
    }

    #[test]
    fn test_deflationary_property() {
        // Adding a combo can only add obligations, never remove them.
        let nucleus_base = ConstraintNucleus::new();
        let nucleus_extended = ConstraintNucleus::new().with_combo(DangerousCombo {
            name: "extra".to_string(),
            required_core_labels: {
                let mut s = BTreeSet::new();
                s.insert(CoreTaintRequirement::PrivateData);
                s.insert(CoreTaintRequirement::UntrustedContent);
                s
            },
            required_ext_labels: BTreeSet::new(),
            mitigation: Obligations::for_operation(Operation::WebFetch),
            risk_grade: TrifectaRisk::Medium,
        });

        // For any taint set, extended obligations are a superset of base obligations
        let test_taints = vec![
            TaintSet::empty(),
            TaintSet::singleton(TaintLabel::PrivateData),
            TaintSet::singleton(TaintLabel::PrivateData)
                .union(&TaintSet::singleton(TaintLabel::UntrustedContent)),
            TaintSet::singleton(TaintLabel::PrivateData)
                .union(&TaintSet::singleton(TaintLabel::UntrustedContent))
                .union(&TaintSet::singleton(TaintLabel::ExfilVector)),
        ];

        for taint in &test_taints {
            let base = nucleus_base.apply(taint);
            let extended = nucleus_extended.apply(taint);
            // Every base obligation must also be in extended
            for op in &base.approvals {
                assert!(
                    extended.approvals.contains(op),
                    "Deflationary violation: base has {:?} but extended doesn't for taint {}",
                    op,
                    taint
                );
            }
        }
    }
}
