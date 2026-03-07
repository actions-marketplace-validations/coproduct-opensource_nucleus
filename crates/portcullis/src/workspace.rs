//! Multi-agent workspace taint composition.
//!
//! When multiple agents share a workspace, their taint sets compose into
//! a shared global taint. This module defines the trait contract for
//! workspace-level taint tracking.
//!
//! ## Mathematical Structure
//!
//! The shared taint is modeled as the **global section** of a taint presheaf:
//! each agent has a local taint set, and the workspace taint is their join
//! (union). When any agent's taint contributes to a dangerous combination,
//! ALL agents in the workspace are subject to the resulting obligations.
//!
//! This is the correct categorical construction: taint flows "up" from agents
//! to the workspace (a colimit), and obligations flow "down" from the workspace
//! to agents (a limit). The adjunction between colimits and limits gives us
//! the soundness guarantee.
//!
//! ## v1.0 Status
//!
//! This is a **trait definition only** — no implementation in v1.0. It
//! establishes the contract that multi-agent composition will satisfy and
//! ensures the [`GradedTaintGuard`](crate::guard::GradedTaintGuard) API is
//! compatible with future shared-taint scenarios.

use crate::capability::Operation;
use crate::guard::{CheckProof, GuardError, TaintSet};

/// Workspace permission context for concurrent agents.
///
/// The shared taint is the global section of the taint presheaf:
/// `Γ(T) = ⋃_{a ∈ Agents} T(a)`
///
/// When the join reaches a dangerous combination, obligations propagate
/// to all agents via the limit construction.
pub trait WorkspaceGuard: Send + Sync {
    /// Record that an agent performed an operation.
    ///
    /// Updates the agent's local taint and recomputes the shared workspace
    /// taint. May block other agents if the shared taint now triggers a
    /// dangerous combination.
    fn record(&self, agent: &str, op: Operation) -> Result<(), GuardError>;

    /// Check if an agent can perform an operation given shared taint.
    ///
    /// The check considers both the agent's local taint and the workspace's
    /// shared taint when evaluating dangerous combinations.
    fn check(&self, agent: &str, op: Operation) -> Result<CheckProof, GuardError>;

    /// Get the current shared workspace taint (the global section).
    fn shared_taint(&self) -> TaintSet;

    /// Get the local taint for a specific agent.
    fn agent_taint(&self, agent: &str) -> Option<TaintSet>;
}
