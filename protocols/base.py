""" base.py
Base Protocol Class for ITK
All protocol drivers inherit from ICSProtocol.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Any, Optional
import json


@dataclass
class Result:
    """Unified result object for all protocol operations."""
    success: bool
    data: Any = None
    error: Optional[str] = None
    protocol: str = "unknown"
    operation: str = "unknown"
    target: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_json(self) -> str:
        """Serialize result to JSON string."""
        return json.dumps(asdict(self), indent=2, default=str)

    def __str__(self) -> str:
        if self.success:
            return f"[+] {self.operation}: {self.data}"
        return f"[-] {self.operation} failed: {self.error}"


class ICSProtocol(ABC):
    def __init__(self, target, port, timeout=5):
        self.target = target
        self.port = port
        self.timeout = timeout
        self.connection = None

    @abstractmethod
    def connect(self):
        """Establish connection to the target."""
        pass

    @abstractmethod
    def get_info(self):
        """Fingerprint the device and return metadata."""
        pass

    @abstractmethod
    def scan(self, range_start, range_end):
        """Enumerate objects/registers in a given range."""
        pass

    @abstractmethod
    def write(self, address, value):
        """Write a value to a specific object/register."""
        pass

    @abstractmethod
    def read(self, address):
        """Read a value from a specific object/register."""
        pass

    @abstractmethod
    def close(self):
        """Close the connection to the target."""
        pass
