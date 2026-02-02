""" session.py
Session Manager for Connection State Caching
Avoids handshake overhead during rapid-fire CTF commands.
"""

import json
import os
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, Any


class SessionManager:
    """Manage cached connection states for rapid tool usage."""

    def __init__(self, session_dir: Optional[str] = None):
        if session_dir:
            self.session_dir = Path(session_dir)
        else:
            self.session_dir = Path.home() / ".itk" / "sessions"
        self.session_dir.mkdir(parents=True, exist_ok=True)
        self._active_sessions: Dict[str, Any] = {}

    def _get_session_key(self, target: str, protocol: str) -> str:
        """Generate unique session key."""
        return f"{protocol}_{target.replace('.', '_').replace(':', '_')}"

    def _get_session_file(self, session_key: str) -> Path:
        """Get path to session file."""
        return self.session_dir / f"{session_key}.json"

    def save(self, target: str, protocol: str, state: Dict[str, Any]) -> bool:
        """Save connection state to cache."""
        session_key = self._get_session_key(target, protocol)
        session_data = {
            "target": target,
            "protocol": protocol,
            "state": state,
            "created": datetime.now().isoformat(),
            "last_used": datetime.now().isoformat(),
        }

        try:
            session_file = self._get_session_file(session_key)
            with open(session_file, "w") as f:
                json.dump(session_data, f, indent=2)
            self._active_sessions[session_key] = session_data
            return True
        except Exception:
            return False

    def load(self, target: str, protocol: str) -> Optional[Dict[str, Any]]:
        """Load cached connection state."""
        session_key = self._get_session_key(target, protocol)

        # Check memory cache first
        if session_key in self._active_sessions:
            return self._active_sessions[session_key]["state"]

        # Try loading from file
        session_file = self._get_session_file(session_key)
        if session_file.exists():
            try:
                with open(session_file, "r") as f:
                    session_data = json.load(f)
                    self._active_sessions[session_key] = session_data
                    return session_data["state"]
            except Exception:
                return None
        return None

    def clear(self, target: Optional[str] = None, protocol: Optional[str] = None):
        """Clear session cache. If target/protocol specified, clear only that session."""
        if target and protocol:
            session_key = self._get_session_key(target, protocol)
            if session_key in self._active_sessions:
                del self._active_sessions[session_key]
            session_file = self._get_session_file(session_key)
            if session_file.exists():
                session_file.unlink()
        else:
            # Clear all sessions
            self._active_sessions.clear()
            for session_file in self.session_dir.glob("*.json"):
                session_file.unlink()

    def list_sessions(self) -> list:
        """List all cached sessions."""
        sessions = []
        for session_file in self.session_dir.glob("*.json"):
            try:
                with open(session_file, "r") as f:
                    data = json.load(f)
                    sessions.append({
                        "target": data["target"],
                        "protocol": data["protocol"],
                        "last_used": data["last_used"],
                    })
            except Exception:
                continue
        return sessions


# Global session manager instance
session_manager = SessionManager()
