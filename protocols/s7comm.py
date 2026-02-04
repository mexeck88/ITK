""" s7comm.py
S7comm Protocol Driver for ITK
Uses python-snap7 for communication.
Replicates s7scan.py functionality via Snap7 with rate limiting.
"""

import snap7
import ctypes
import logging
import time
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
        """Establish connection to S7 PLC using standard Rack/Slot."""
        try:
            self.client = snap7.client.Client()
            self.client.connect(self.target, self.rack, self.slot, self.port)
            
            if self.client.get_connected():
                return Result(True, data={"connected": True}, protocol="s7", operation="connect", target=f"{self.target}:{self.port}")
            else:
                return Result(False, error="Connection failed", protocol="s7", operation="connect")
        except Exception as e:
            return Result(False, error=str(e), protocol="s7", operation="connect")

    def connect_tsap(self, local_tsap: int, remote_tsap: int) -> int:
        """
        Connect explicitly using TSAPs.
        Returns:
            0: Failed
            1: Fully Connected
            2: Partial Connection (Bad PDU - likely valid TSAP but handshake failed)
        """
        try:
            # 1. Clean up previous client completely
            if self.client:
                try:
                    self.client.disconnect()
                    self.client.destroy()
                except: pass
            
            # 2. Create new client
            self.client = snap7.client.Client()
            
            # 3. Set IP and TSAPs first
            self.client.set_connection_params(self.target, local_tsap, remote_tsap)
            
            if self.port != 102:
                self.client.library.Cli_SetParam(self.client.pointer, 2, ctypes.byref(ctypes.c_int(self.port)))
            
            # 5. Connect
            self.client.connect()
            
            if self.client.get_connected():
                return 1
            return 0
            
        except Exception as e:
            msg = str(e)
            if "Bad PDU" in msg or "ISO" in msg:
                return 2
            return 0

    def close(self) -> Result:
        """Close connection."""
        if self.client:
            try:
                self.client.disconnect()
                self.client.destroy()
            except: pass
            self.client = None
        return Result(True, data={"disconnected": True}, protocol="s7", operation="close")

    def get_full_device_info(self) -> Dict[str, Any]:
        """Reads critical SZL IDs."""
        info = {
            "module_identification": [], 
            "component_identification": [], 
            "protection": {},            
            "ethernet": []               
        }

        if not self.client or not self.client.get_connected():
            return info

        # Try to read SZL IDs. Fail silently if they don't exist.
        for szl_id, key in [(0x0011, "module_identification"), (0x001C, "component_identification"), (0x0232, "protection"), (0x0037, "ethernet")]:
            try:
                szl = self.client.read_szl(szl_id)
                for part in szl:
                    if szl_id == 0x0011:
                         info[key].append({"index": part.index, "data": part.data.hex(), "ascii": self._safe_ascii_decode(part.data)})
                    elif szl_id == 0x001C:
                        info[key].append({"index": part.index, "value": self._safe_ascii_decode(part.data).strip()})
                    elif szl_id == 0x0232:
                        info[key] = {"raw": part.data.hex(), "level": part.data[1] if len(part.data) > 1 else "Unknown"}
                    elif szl_id == 0x0037:
                        info[key].append({"index": part.index, "data": part.data.hex()})
            except: pass
        
        return info

    def scan_tsaps(self) -> Result:
        """
        Slow, Robust Brute-force scan of TSAPs.
        """
        self._suppress_snap7_logs()
        found_modules = []
        checked_sigs = set()

        print(f"[*] Starting Robust TSAP Scan on {self.target}:{self.port}...")
        print("    (Scanning slowly to avoid DOSing the target...)")

        # 1. Define Priority Checks (Common Racks/Slots and LOGO settings)
        priority_checks = [
            (0x0100, 0x0102), # Rack 0, Slot 2 (S7-300)
            (0x0100, 0x0100), # Rack 0, Slot 0 (S7-1200)
            (0x0100, 0x0101), # Rack 0, Slot 1 (S7-1200/1500)
            (0x0100, 0x0200), # LOGO! Default
            (0x0100, 0x0201),
            (0x0100, 0x0301),
            (0x0100, 0x0300), 
            # Symmetric Pairs (Local == Remote) - Required for some simulators
            (0x1000, 0x1000), 
            (0x2000, 0x2000), 
            (0x2000, 0x2001), 
            (0x3000, 0x3000),
            (0x4D57, 0x4D57),
            # Try finding the "Bad PDU" source from your first scan
            (0x0100, 0x0002),
        ]

        # 2. Add Standard Ranges (Rack 0, Slots 0-16)
        # 0x0100 (Source) -> 0x01xx, 0x02xx, 0x03xx (Dest)
        for r_tsap in range(0x0100, 0x0310):
            priority_checks.append((0x0100, r_tsap)) # Standard PG
            priority_checks.append((r_tsap, r_tsap)) # Symmetric

        count = 0
        for local, remote in priority_checks:
            sig = (local, remote)
            if sig in checked_sigs: continue
            checked_sigs.add(sig)
            count += 1

            if (count % 20) == 0:
                print(f"    ...checked {count} pairs (current: L={hex(local)} R={hex(remote)})")

            # CRITICAL: Sleep to prevent socket exhaustion on target
            time.sleep(0.05)

            status = self.connect_tsap(local_tsap=local, remote_tsap=remote)
            
            if status > 0:
                status_str = "Full Access" if status == 1 else "Partial (Bad PDU)"
                print(f"\n[+] FOUND VALID TSAP! Local: {hex(local)}, Remote: {hex(remote)} ({status_str})")
                
                details = {}
                cpu_state = "Unknown"
                
                if status == 1:
                    details = self.get_full_device_info()
                    try:
                        cpu_state = self.client.get_cpu_state()
                    except: pass
                
                found_modules.append({
                    "tsap": hex(remote),
                    "local_tsap": hex(local),
                    "status": status_str,
                    "cpu_state": cpu_state,
                    "info": details
                })
                
                self.close()
                # Stop on first finding
                break 
        
        return Result(
            success=len(found_modules) > 0,
            data={"modules": found_modules},
            protocol="s7",
            operation="tsap_scan",
            target=self.target
        )

    def read(self, address: str, type: str = 'db', size: int = 1) -> Result:
        """
        Reads data from a specified S7 memory area.

        Args:
            address (str): The address to read.
                           For 'db': Format is 'DB_NUMBER.OFFSET' (e.g., '1.0').
                           For others: Format is byte offset (e.g., '10').
            type (str): The memory area to access.
                        Options: 'db' (Data Block), 'marker' (Flags/Merkers),
                        'input' (Process Input), 'output' (Process Output).
            size (int): Number of bytes to read.

        Returns:
            Result: Contains bytes, hex string, and ASCII representation if successful.
        """
        if not self.client or not self.client.get_connected():
            return Result(False, error="Not connected", protocol="s7", operation="read")

        try:
            data = None

            if type == 'db':
                if '.' not in address: return Result(False, error="Invalid DB fmt", protocol="s7")
                db, off = map(int, address.split('.'))
                data = self.client.db_read(db, off, size)

            elif type == 'marker': data = self.client.mb_read(int(address), size)
            elif type == 'input': data = self.client.eb_read(int(address), size)
            elif type == 'output': data = self.client.ab_read(int(address), size)

            return Result(True, data={"bytes": list(data), "hex": data.hex(), "ascii": self._safe_ascii_decode(data)}, protocol="s7")

        except Exception as e: return Result(False, error=str(e), protocol="s7")

    def write(self, address: str, value: int, type: str = 'db') -> Result:
        """
        Writes a single byte value to a specified S7 memory area.

        Args:
            address (str): Target address (format depends on type, see read()).
            value (int): The byte value to write (0-255).
            type (str): The memory area ('db', 'marker', 'output').
                        Note: Writing to 'input' is generally not supported directly.

        Returns:
            Result: Success status.
        """
        if not self.client or not self.client.get_connected():
            return Result(False, error="Not connected", protocol="s7", operation="write")

        try:
            data = bytearray([int(value)])

            if type == 'db':
                db, off = map(int, address.split('.'))
                self.client.db_write(db, off, data)

            elif type == 'marker': self.client.mb_write(int(address), data)
            elif type == 'output': self.client.ab_write(int(address), data)

            return Result(True, data={"written": True, "val": value}, protocol="s7")

        except Exception as e: return Result(False, error=str(e), protocol="s7")

    def scan(self, start_db=1, end_db=100, strategy="auto") -> Result:
        """
        Enumerates valid Data Blocks (DBs) and gathers device information.
        
        This method brute-forces a range of DB numbers to see which ones exist
        and are readable.

        Args:
            start_db (int): Starting DB number.
            end_db (int): Ending DB number.
            strategy (str): Scan strategy (reserved for future use).

        Returns:
            Result: List of found DBs and device SZL information.
        """
        if not self.client or not self.client.get_connected():
            return Result(False, error="Not connected", protocol="s7", operation="scan")

        self._suppress_snap7_logs()
        found_dbs = []

        for db in range(start_db, end_db + 1):
            try:
                self.client.db_read(db, 0, 1)
                found_dbs.append(db)

            except: pass

        info = self.get_full_device_info()
        return Result(True, data={"found_dbs": found_dbs, "info": info}, protocol="s7", operation="scan")

    def get_info(self) -> Result:
        """
        CLI Wrapper to retrieve full device fingerprint/SZL details.
        """
        if not self.client or not self.client.get_connected(): return Result(False, error="Not connected", protocol="s7")
        return Result(True, data=self.get_full_device_info(), protocol="s7")

    @classmethod
    def scan_network(cls, target: str, port: int = 102, timeout: int = 5) -> Result:
        """
        Factory method for high-level discovery.
        Instantiates the protocol and performs an aggressive TSAP scan.
        """
        proto = cls(target, port, timeout)
        return proto.scan_tsaps()

    def _safe_ascii_decode(self, data: bytes) -> str:
        """
        Helper: Decodes bytes to ASCII, replacing non-printable characters with dots.
        Useful for visualizing memory dumps.
        """
        return ''.join(chr(b) if 32 <= b <= 126 else '.' for b in data)

    def _suppress_snap7_logs(self):
        """
        Helper: Sets internal Snap7 loggers to CRITICAL to suppress
        'ISO : Bad PDU format' errors during scanning.
        """
        for name in logging.root.manager.loggerDict:
            if "snap7" in name:
                logging.getLogger(name).setLevel(logging.CRITICAL)