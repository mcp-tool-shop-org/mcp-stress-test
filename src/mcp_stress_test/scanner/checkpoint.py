"""Checkpoint management for stress test sessions.

Integrates with context-window-manager for freeze/thaw functionality,
enabling session persistence and rollback during stress testing.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from mcp_stress_test.models import (
    ScanResult,
    ToolSchema,
)


@dataclass
class StressCheckpoint:
    """Represents a checkpoint in a stress test session."""

    checkpoint_id: str
    session_id: str
    timestamp: datetime
    invocation_count: int
    tool_state: dict[str, Any]
    scan_results: list[ScanResult]
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert checkpoint to serializable dict."""
        return {
            "checkpoint_id": self.checkpoint_id,
            "session_id": self.session_id,
            "timestamp": self.timestamp.isoformat(),
            "invocation_count": self.invocation_count,
            "tool_state": self.tool_state,
            "scan_results": [r.model_dump(mode="json") for r in self.scan_results],
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> StressCheckpoint:
        """Create checkpoint from dict."""
        return cls(
            checkpoint_id=data["checkpoint_id"],
            session_id=data["session_id"],
            timestamp=datetime.fromisoformat(data["timestamp"]),
            invocation_count=data["invocation_count"],
            tool_state=data["tool_state"],
            scan_results=[ScanResult(**r) for r in data["scan_results"]],
            metadata=data.get("metadata", {}),
        )


@dataclass
class SessionState:
    """Current state of a stress test session."""

    session_id: str
    started_at: datetime
    current_invocation: int = 0
    tools_tested: list[str] = field(default_factory=list)
    mutations_applied: int = 0
    attacks_detected: int = 0
    attacks_missed: int = 0
    checkpoints: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert state to serializable dict."""
        return {
            "session_id": self.session_id,
            "started_at": self.started_at.isoformat(),
            "current_invocation": self.current_invocation,
            "tools_tested": self.tools_tested,
            "mutations_applied": self.mutations_applied,
            "attacks_detected": self.attacks_detected,
            "attacks_missed": self.attacks_missed,
            "checkpoints": self.checkpoints,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SessionState:
        """Create state from dict."""
        return cls(
            session_id=data["session_id"],
            started_at=datetime.fromisoformat(data["started_at"]),
            current_invocation=data.get("current_invocation", 0),
            tools_tested=data.get("tools_tested", []),
            mutations_applied=data.get("mutations_applied", 0),
            attacks_detected=data.get("attacks_detected", 0),
            attacks_missed=data.get("attacks_missed", 0),
            checkpoints=data.get("checkpoints", []),
        )


class CheckpointManager:
    """Manages checkpoints for stress test sessions.

    Provides local file-based storage with optional CWM integration
    for distributed sessions.
    """

    def __init__(
        self,
        storage_dir: Path | str | None = None,
        session_id: str | None = None,
        enable_cwm: bool = False,
    ):
        """Initialize checkpoint manager.

        Args:
            storage_dir: Directory for checkpoint storage. Defaults to .stress-checkpoints
            session_id: Session identifier. Auto-generated if not provided.
            enable_cwm: Enable context-window-manager integration.
        """
        self.storage_dir = Path(storage_dir) if storage_dir else Path(".stress-checkpoints")
        self.storage_dir.mkdir(parents=True, exist_ok=True)

        self.session_id = session_id or self._generate_session_id()
        self.enable_cwm = enable_cwm

        # Initialize session state
        self._state = SessionState(
            session_id=self.session_id,
            started_at=datetime.now(),
        )

        # Load existing state if resuming
        self._load_session_state()

    def _generate_session_id(self) -> str:
        """Generate unique session ID."""
        timestamp = datetime.now().isoformat()
        return hashlib.sha256(timestamp.encode()).hexdigest()[:12]

    def _load_session_state(self) -> None:
        """Load existing session state if available."""
        state_file = self.storage_dir / f"session_{self.session_id}.json"
        if state_file.exists():
            with open(state_file) as f:
                data = json.load(f)
                self._state = SessionState.from_dict(data)

    def _save_session_state(self) -> None:
        """Save current session state."""
        state_file = self.storage_dir / f"session_{self.session_id}.json"
        with open(state_file, "w") as f:
            json.dump(self._state.to_dict(), f, indent=2)

    @property
    def state(self) -> SessionState:
        """Get current session state."""
        return self._state

    def create_checkpoint(
        self,
        tool: ToolSchema,
        scan_results: list[ScanResult],
        metadata: dict[str, Any] | None = None,
    ) -> StressCheckpoint:
        """Create a checkpoint of the current test state.

        Args:
            tool: Current tool being tested.
            scan_results: Scan results up to this point.
            metadata: Additional metadata to store.

        Returns:
            Created checkpoint.
        """
        checkpoint_id = f"cp_{self.session_id}_{self._state.current_invocation}"

        checkpoint = StressCheckpoint(
            checkpoint_id=checkpoint_id,
            session_id=self.session_id,
            timestamp=datetime.now(),
            invocation_count=self._state.current_invocation,
            tool_state=tool.model_dump(),
            scan_results=scan_results,
            metadata=metadata or {},
        )

        # Save checkpoint
        checkpoint_file = self.storage_dir / f"{checkpoint_id}.json"
        with open(checkpoint_file, "w") as f:
            json.dump(checkpoint.to_dict(), f, indent=2)

        # Update session state
        self._state.checkpoints.append(checkpoint_id)
        self._save_session_state()

        # CWM integration placeholder
        if self.enable_cwm:
            self._cwm_freeze(checkpoint)

        return checkpoint

    def restore_checkpoint(self, checkpoint_id: str) -> StressCheckpoint:
        """Restore session from a checkpoint.

        Args:
            checkpoint_id: ID of checkpoint to restore.

        Returns:
            Restored checkpoint.

        Raises:
            FileNotFoundError: If checkpoint doesn't exist.
        """
        checkpoint_file = self.storage_dir / f"{checkpoint_id}.json"

        if not checkpoint_file.exists():
            raise FileNotFoundError(f"Checkpoint not found: {checkpoint_id}")

        with open(checkpoint_file) as f:
            data = json.load(f)

        checkpoint = StressCheckpoint.from_dict(data)

        # Restore session state to checkpoint
        self._state.current_invocation = checkpoint.invocation_count

        # CWM integration placeholder
        if self.enable_cwm:
            self._cwm_thaw(checkpoint)

        return checkpoint

    def list_checkpoints(self) -> list[StressCheckpoint]:
        """List all checkpoints for current session.

        Returns:
            List of checkpoints ordered by timestamp.
        """
        checkpoints = []

        for checkpoint_id in self._state.checkpoints:
            checkpoint_file = self.storage_dir / f"{checkpoint_id}.json"
            if checkpoint_file.exists():
                with open(checkpoint_file) as f:
                    data = json.load(f)
                checkpoints.append(StressCheckpoint.from_dict(data))

        return sorted(checkpoints, key=lambda c: c.timestamp)

    def get_latest_checkpoint(self) -> StressCheckpoint | None:
        """Get the most recent checkpoint.

        Returns:
            Latest checkpoint or None if no checkpoints exist.
        """
        checkpoints = self.list_checkpoints()
        return checkpoints[-1] if checkpoints else None

    def delete_checkpoint(self, checkpoint_id: str) -> bool:
        """Delete a checkpoint.

        Args:
            checkpoint_id: ID of checkpoint to delete.

        Returns:
            True if deleted, False if not found.
        """
        checkpoint_file = self.storage_dir / f"{checkpoint_id}.json"

        if checkpoint_file.exists():
            checkpoint_file.unlink()
            if checkpoint_id in self._state.checkpoints:
                self._state.checkpoints.remove(checkpoint_id)
                self._save_session_state()
            return True

        return False

    def record_mutation(self, detected: bool) -> None:
        """Record a mutation test result.

        Args:
            detected: Whether the attack was detected by scanner.
        """
        self._state.mutations_applied += 1
        if detected:
            self._state.attacks_detected += 1
        else:
            self._state.attacks_missed += 1
        self._save_session_state()

    def record_tool_tested(self, tool_name: str) -> None:
        """Record that a tool was tested.

        Args:
            tool_name: Name of the tested tool.
        """
        if tool_name not in self._state.tools_tested:
            self._state.tools_tested.append(tool_name)
            self._save_session_state()

    def increment_invocation(self) -> int:
        """Increment invocation counter.

        Returns:
            New invocation count.
        """
        self._state.current_invocation += 1
        self._save_session_state()
        return self._state.current_invocation

    def get_detection_rate(self) -> float:
        """Calculate current detection rate.

        Returns:
            Detection rate as percentage (0-100).
        """
        total = self._state.attacks_detected + self._state.attacks_missed
        if total == 0:
            return 0.0
        return (self._state.attacks_detected / total) * 100

    def get_summary(self) -> dict[str, Any]:
        """Get session summary.

        Returns:
            Summary statistics for the session.
        """
        return {
            "session_id": self.session_id,
            "started_at": self._state.started_at.isoformat(),
            "duration_seconds": (datetime.now() - self._state.started_at).total_seconds(),
            "invocations": self._state.current_invocation,
            "tools_tested": len(self._state.tools_tested),
            "mutations_applied": self._state.mutations_applied,
            "attacks_detected": self._state.attacks_detected,
            "attacks_missed": self._state.attacks_missed,
            "detection_rate": self.get_detection_rate(),
            "checkpoints_created": len(self._state.checkpoints),
        }

    def cleanup(self, keep_latest: int = 3) -> int:
        """Clean up old checkpoints, keeping the most recent ones.

        Args:
            keep_latest: Number of recent checkpoints to keep.

        Returns:
            Number of checkpoints deleted.
        """
        checkpoints = self.list_checkpoints()

        if len(checkpoints) <= keep_latest:
            return 0

        # Delete oldest checkpoints
        to_delete = checkpoints[:-keep_latest]
        deleted = 0

        for cp in to_delete:
            if self.delete_checkpoint(cp.checkpoint_id):
                deleted += 1

        return deleted

    # =========================================================================
    # CWM Integration Methods (placeholders for context-window-manager)
    # =========================================================================

    def _cwm_freeze(self, checkpoint: StressCheckpoint) -> None:
        """Freeze checkpoint to CWM.

        Placeholder for context-window-manager integration.
        When CWM is available, this will call window_freeze.
        """
        # TODO: Implement CWM freeze when MCP is available
        # Example CWM call:
        # cwm.window_freeze(
        #     session_id=checkpoint.session_id,
        #     window_name=f"stress_test_{checkpoint.checkpoint_id}",
        #     prompt_prefix=json.dumps(checkpoint.to_dict()),
        #     description=f"Stress test checkpoint at invocation {checkpoint.invocation_count}",
        # )
        pass

    def _cwm_thaw(self, checkpoint: StressCheckpoint) -> None:
        """Thaw checkpoint from CWM.

        Placeholder for context-window-manager integration.
        When CWM is available, this will call window_thaw.
        """
        # TODO: Implement CWM thaw when MCP is available
        # Example CWM call:
        # cwm.window_thaw(
        #     window_name=f"stress_test_{checkpoint.checkpoint_id}",
        # )
        pass

    def cwm_list_windows(self) -> list[dict[str, Any]]:
        """List available CWM windows for this session.

        Returns:
            List of CWM windows (empty if CWM not enabled).
        """
        if not self.enable_cwm:
            return []

        # TODO: Implement CWM window listing
        # cwm.window_list(session_id=self.session_id)
        return []


class CheckpointIterator:
    """Iterator for replaying checkpoints in sequence."""

    def __init__(self, manager: CheckpointManager):
        """Initialize with checkpoint manager.

        Args:
            manager: CheckpointManager to iterate over.
        """
        self.manager = manager
        self.checkpoints = manager.list_checkpoints()
        self.index = 0

    def __iter__(self) -> Iterator[StressCheckpoint]:
        """Return iterator."""
        return self

    def __next__(self) -> StressCheckpoint:
        """Get next checkpoint."""
        if self.index >= len(self.checkpoints):
            raise StopIteration

        checkpoint = self.checkpoints[self.index]
        self.index += 1
        return checkpoint

    def reset(self) -> None:
        """Reset iterator to beginning."""
        self.index = 0

    def jump_to(self, checkpoint_id: str) -> StressCheckpoint:
        """Jump to specific checkpoint.

        Args:
            checkpoint_id: ID of checkpoint to jump to.

        Returns:
            The checkpoint.

        Raises:
            ValueError: If checkpoint not found.
        """
        for i, cp in enumerate(self.checkpoints):
            if cp.checkpoint_id == checkpoint_id:
                self.index = i + 1
                return cp

        raise ValueError(f"Checkpoint not found: {checkpoint_id}")
