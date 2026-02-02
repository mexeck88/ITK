""" s7comm.py
S7comm Protocol Driver for ITK
Uses python-snap7 for communication.
"""

import snap7
from snap7.util import set_bool, get_bool, set_int, get_int, set_real, get_real, set_string, get_string
from protocols.base import ICSProtocol, Result
from typing import Any, List, Dict, Optional


class S7Protocol(ICSProtocol):
    """S7comm (Siemens) protocol implementation."""

    def __init__(self, target: str, port: int = 102, timeout: int = 5, rack: int = 0, slot: int = 2):
        super().__init__(target, port, timeout)
        self.rack = rack
        self.slot = slot
        self.client: Optional[snap7.client.Client] = None

    def connect(self) -> Result:
        """Establish connection to S7 PLC."""
        try:
            self.client = snap7.client.Client()
            self.client.connect(self.target, self.rack, self.slot, self.port)
            
            if self.client.get_connected():
                return Result(
                    success=True,
                    data={"connected": True},
                    protocol="s7",
                    operation="connect",
                    target=f"{self.target}:{self.port}"
                )
            else:
                return Result(
                    success=False,
                    error="Connection failed",
                    protocol="s7",
                    operation="connect",
                    target=f"{self.target}:{self.port}"
                )
        except Exception as e:
            return Result(
                success=False,
                error=str(e),
                protocol="s7",
                operation="connect",
                target=f"{self.target}:{self.port}"
            )

    def close(self) -> Result:
        """Close connection."""
        if self.client:
            self.client.disconnect()
            self.client.destroy()
            self.client = None
        return Result(
            success=True,
            data={"disconnected": True},
            protocol="s7",
            operation="close",
            target=f"{self.target}:{self.port}"
        )

    def get_info(self) -> Result:
        """Get CPU Info."""
        if not self.client or not self.client.get_connected():
            return Result(success=False, error="Not connected", protocol="s7", operation="get_info")

        try:
            # Read CPU Info (SZL ID 0x001C index 0)
            # Python-snap7 doesn't have a direct get_cpu_info helper that returns dict,
            # but we can try basic connectivity check + PDU size
            pdu_length = self.client.get_pdu_length()
            
            # Check if execution status is available
            cpu_state = self.client.get_cpu_state()
            
            return Result(
                success=True,
                data={
                    "pdu_length": pdu_length,
                    "cpu_state": cpu_state,
                    "rack": self.rack,
                    "slot": self.slot
                },
                protocol="s7",
                operation="info",
                target=f"{self.target}:{self.port}"
            )
        except Exception as e:
            return Result(success=False, error=str(e), protocol="s7", operation="info")

    def read(self, address: str, type: str = 'db', size: int = 1) -> Result:
        """
        Read from S7 memory.
        
        Args:
            address: Address string (e.g., "1.10" for DB1 byte 10, or "M10" for Marker 10)
            type: 'db', 'input', 'output', 'marker'
            size: Number of bytes to read
        """
        if not self.client or not self.client.get_connected():
            return Result(success=False, error="Not connected", protocol="s7", operation="read")

        try:
            data = None
            
            if type == 'db':
                # Parse DB.OFFSET (e.g., "1.10")
                if '.' not in address:
                    return Result(success=False, error="Invalid DB address format. Use DB_NUM.OFFSET (e.g., 1.0)", protocol="s7")
                
                db_num, offset = map(int, address.split('.'))
                data = self.client.db_read(db_num, offset, size)
                
            elif type == 'marker':
                # Parse OFFSET (e.g., "10")
                offset = int(address)
                data = self.client.mb_read(offset, size)
                
            elif type == 'input':
                offset = int(address)
                data = self.client.eb_read(offset, size)
                
            elif type == 'output':
                offset = int(address)
                data = self.client.ab_read(offset, size)
                
            else:
                return Result(success=False, error=f"Unknown type: {type}", protocol="s7", operation="read")

            return Result(
                success=True,
                data={
                    "address": address,
                    "type": type,
                    "size": size,
                    "bytes": list(data),
                    "hex": data.hex(),
                    "ascii": self._safe_ascii_decode(data)
                },
                protocol="s7",
                operation="read",
                target=f"{self.target}:{self.port}"
            )

        except Exception as e:
            return Result(success=False, error=str(e), protocol="s7", operation="read")

    def write(self, address: str, value: Any, type: str = 'db') -> Result:
        """
        Write to S7 memory.
        Currently supports writing raw bytes (integer value) or bytearrays.
        
        Args:
            address: Address string (e.g. "1.10")
            value: Integer (0-255) to write as a single byte
            type: 'db', 'output', 'marker'
        """
        if not self.client or not self.client.get_connected():
            return Result(success=False, error="Not connected", protocol="s7", operation="write")

        try:
            # Prepare data
            data = bytearray([int(value)])
            
            if type == 'db':
                if '.' not in address:
                    return Result(success=False, error="Invalid DB address format. Use DB_NUM.OFFSET", protocol="s7")
                db_num, offset = map(int, address.split('.'))
                self.client.db_write(db_num, offset, data)
                
            elif type == 'marker':
                offset = int(address)
                self.client.mb_write(offset, data)
                
            elif type == 'output':
                offset = int(address)
                self.client.ab_write(offset, data)
                
            else:
                return Result(success=False, error=f"Unknown type: {type}", protocol="s7", operation="write")

            return Result(
                success=True,
                data={
                    "address": address,
                    "type": type,
                    "value": value,
                    "written": True
                },
                protocol="s7",
                operation="write",
                target=f"{self.target}:{self.port}"
            )

        except Exception as e:
            return Result(success=False, error=str(e), protocol="s7", operation="write")

    def scan(self, start_db: int = 1, end_db: int = 100) -> Result:
        """
        Scan for valid Data Blocks.
        Since there's no "list_dbs" command, we bruteforce read 1 byte from each DB.
        """
        if not self.client or not self.client.get_connected():
            return Result(success=False, error="Not connected", protocol="s7", operation="scan")

        found_dbs = []
        
        # Also get CPU info
        cpu_info = self.get_info()
        
        for db in range(start_db, end_db + 1):
            try:
                # Try to read 1 byte from offset 0
                self.client.db_read(db, 0, 1)
                found_dbs.append(db)
            except:
                pass

        return Result(
            success=True,
            data={
                "found_dbs": found_dbs,
                "count": len(found_dbs),
                "cpu_info": cpu_info.data if cpu_info.success else None
            },
            protocol="s7",
            operation="scan",
            target=f"{self.target}:{self.port}"
        )

    def _safe_ascii_decode(self, data: bytes) -> str:
        """Safely decode bytes to ASCII, replacing non-printables."""
        return ''.join(chr(b) if 32 <= b <= 126 else '.' for b in data)
