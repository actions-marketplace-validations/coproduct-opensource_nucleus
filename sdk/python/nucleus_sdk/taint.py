"""Session-scoped taint tracking with trifecta gate.

Mirrors the Verus-verified taint_core decision kernel from portcullis.
The three taint labels form a 3-bool semilattice — taint can only increase
(monotone union), never decrease within a session.

When all three labels co-occur (the "trifecta"), exfiltration-capable
operations require explicit approval before proceeding.
"""

from __future__ import annotations

from enum import Enum, auto
from typing import FrozenSet, Optional


class TaintLabel(Enum):
    """The three legs of the taint trifecta."""

    PRIVATE_DATA = auto()
    """Private data was accessed (read, glob, grep)."""

    UNTRUSTED_CONTENT = auto()
    """Untrusted external content was ingested (web_fetch, web_search)."""

    EXFIL_VECTOR = auto()
    """An exfiltration-capable operation was performed (run, git_push, create_pr)."""


# Map SDK operation names to their taint contribution.
# None means the operation is taint-neutral (no contribution).
_OPERATION_TAINT: dict[str, Optional[TaintLabel]] = {
    "fs.read": TaintLabel.PRIVATE_DATA,
    "fs.write": None,
    "fs.glob": TaintLabel.PRIVATE_DATA,
    "fs.grep": TaintLabel.PRIVATE_DATA,
    "net.fetch": TaintLabel.UNTRUSTED_CONTENT,
    "net.search": TaintLabel.UNTRUSTED_CONTENT,
    "git.push": TaintLabel.EXFIL_VECTOR,
    "git.create_pr": TaintLabel.EXFIL_VECTOR,
    "git.commit": None,
    "git.add": None,
    "run": TaintLabel.EXFIL_VECTOR,
}

# Operations where RunBash-style omnibus projection applies.
# These conservatively project PRIVATE_DATA + EXFIL_VECTOR because
# a shell command can both read files and exfiltrate data.
_OMNIBUS_OPERATIONS = frozenset({"run"})

# Operations that require approval when trifecta would complete.
_EXFIL_OPERATIONS = frozenset({"run", "git.push", "git.create_pr"})


class TaintSet:
    """Monotone 3-bool taint accumulator.

    Mirrors portcullis::guard::TaintSet. The set can only grow via union —
    there is no way to remove a label once added.
    """

    __slots__ = ("_labels",)

    def __init__(self, labels: Optional[FrozenSet[TaintLabel]] = None) -> None:
        self._labels: FrozenSet[TaintLabel] = labels or frozenset()

    @classmethod
    def empty(cls) -> TaintSet:
        return cls()

    def union(self, other: TaintSet) -> TaintSet:
        return TaintSet(self._labels | other._labels)

    def with_label(self, label: TaintLabel) -> TaintSet:
        return TaintSet(self._labels | {label})

    def contains(self, label: TaintLabel) -> bool:
        return label in self._labels

    def is_trifecta_complete(self) -> bool:
        return (
            TaintLabel.PRIVATE_DATA in self._labels
            and TaintLabel.UNTRUSTED_CONTENT in self._labels
            and TaintLabel.EXFIL_VECTOR in self._labels
        )

    @property
    def labels(self) -> FrozenSet[TaintLabel]:
        return self._labels

    def summary(self) -> str:
        if not self._labels:
            return "clean"
        parts = []
        if TaintLabel.PRIVATE_DATA in self._labels:
            parts.append("private_data")
        if TaintLabel.UNTRUSTED_CONTENT in self._labels:
            parts.append("untrusted_content")
        if TaintLabel.EXFIL_VECTOR in self._labels:
            parts.append("exfil_vector")
        return "+".join(parts)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, TaintSet):
            return NotImplemented
        return self._labels == other._labels

    def __repr__(self) -> str:
        return f"TaintSet({self.summary()})"


def classify_operation(operation: str) -> Optional[TaintLabel]:
    """Map an operation name to its taint label.

    Mirrors portcullis::taint_core::classify_operation.
    """
    return _OPERATION_TAINT.get(operation)


def project_taint(current: TaintSet, operation: str) -> TaintSet:
    """Project what the taint set WOULD be if this operation executes.

    Mirrors portcullis::taint_core::project_taint. RunBash-style operations
    are treated as omnibus (conservatively project both PRIVATE_DATA and
    EXFIL_VECTOR).
    """
    if operation in _OMNIBUS_OPERATIONS:
        return (
            current.with_label(TaintLabel.PRIVATE_DATA).with_label(
                TaintLabel.EXFIL_VECTOR
            )
        )
    label = classify_operation(operation)
    if label is not None:
        return current.with_label(label)
    return current


def should_deny(
    current: TaintSet,
    operation: str,
    trifecta_enabled: bool = True,
) -> bool:
    """Pure denial decision: should this operation be blocked?

    Mirrors portcullis::taint_core::should_deny.
    Returns True if the operation would complete the trifecta and
    the operation is exfiltration-capable.
    """
    if not trifecta_enabled:
        return False
    requires_approval = operation in _EXFIL_OPERATIONS
    if not requires_approval:
        return False
    projected = project_taint(current, operation)
    return projected.is_trifecta_complete()


def apply_record(current: TaintSet, operation: str) -> TaintSet:
    """Record a successful operation's taint contribution.

    Mirrors portcullis::taint_core::apply_record. Unlike project_taint,
    this does NOT use omnibus projection — it records what actually happened.
    """
    label = classify_operation(operation)
    if label is not None:
        return current.with_label(label)
    return current


class TaintGuard:
    """Session-scoped taint guard that tool handles call before/after operations.

    This is the Python equivalent of SessionTaint in nucleus-mcp's Rust code.
    Tool handles call ``check()`` before executing and ``record()`` after
    a successful execution.
    """

    def __init__(self, trifecta_enabled: bool = True) -> None:
        self._taint = TaintSet.empty()
        self._trifecta_enabled = trifecta_enabled

    @property
    def taint(self) -> TaintSet:
        return self._taint

    def check(self, operation: str) -> None:
        """Raise TrifectaBlocked if the operation would complete the trifecta.

        Must be called BEFORE the operation executes. This is the pre-call
        gate that blocks exfiltration when private data and untrusted content
        have both been accessed.
        """
        if should_deny(self._taint, operation, self._trifecta_enabled):
            from .errors import TrifectaBlocked

            raise TrifectaBlocked(
                f"trifecta blocked: {operation} would complete taint trifecta "
                f"({self._taint.summary()}). The session has accessed private data "
                f"and untrusted content -- this exfiltration-capable operation "
                f"requires explicit approval.",
                kind="trifecta_blocked",
                operation=operation,
            )

    def record(self, operation: str) -> None:
        """Record a successful operation's taint contribution.

        Must be called AFTER the operation succeeds. Taint accumulation
        is monotone — it can only increase.
        """
        self._taint = apply_record(self._taint, operation)

    def summary(self) -> str:
        return self._taint.summary()
