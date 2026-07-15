""" modbus.py
Modbus TCP Protocol Driver for ITK
Uses pymodbus for all of the low level protocol manipulation.
This module is called by itk.py for the toolkit functions for modbus.
"""

from pymodbus.client import ModbusTcpClient
from pymodbus.exceptions import ModbusException, ConnectionException
from pymodbus.pdu import ExceptionResponse
from protocols.base import ICSProtocol, Result
from typing import Optional, List, Dict, Any
import inspect
import logging

# Modbus exception codes that mean "the addressed device is NOT there"
# (as opposed to a device that answered but rejected the specific request).
#   0x0A GATEWAY_PATH_UNAVAILABLE
#   0x0B GATEWAY_TARGET_DEVICE_FAILED_TO_RESPOND
_GATEWAY_ABSENT_CODES = (0x0A, 0x0B)

# pymodbus renamed the unit/slave keyword across the 3.x line:
#   3.0 - 3.6:  read_holding_registers(addr, count=1, slave=0, **kwargs)
#   3.7+     :  read_holding_registers(addr, count=1, device_id=0, ...)
# Because the older signature swallows unknown kwargs via **kwargs, passing
# "device_id=" to pymodbus 3.5.x is SILENTLY IGNORED and every request goes to
# the default slave 0 -- which is why ITK could never reach unit 52. Detect the
# correct keyword from the installed version instead of hard-coding one.
try:
    _params = inspect.signature(ModbusTcpClient.read_holding_registers).parameters
    _UNIT_KW = "device_id" if "device_id" in _params else "slave"
except (ValueError, TypeError):  # pragma: no cover - defensive
    _UNIT_KW = "slave"


class ModbusProtocol(ICSProtocol):
    """Modbus TCP protocol implementation."""

    # Register type mapping
    REGISTER_TYPES = {
        'coil': 'coils',
        'discrete': 'discrete_inputs', 
        'input': 'input_registers',
        'holding': 'holding_registers'
    }

    def __init__(self, target: str, port: int = 502, timeout: int = 5, unit_id: int = 1):
        super().__init__(target, port, timeout)
        self.unit_id = unit_id
        self.client: Optional[ModbusTcpClient] = None

    def _uk(self, unit_id: Optional[int] = None) -> Dict[str, int]:
        """Return the correct unit/slave keyword for the installed pymodbus."""
        return {_UNIT_KW: self.unit_id if unit_id is None else unit_id}

    def connect(self) -> Result:
        """Establish connection to Modbus server."""
        try:
            self.client = ModbusTcpClient(
                host=self.target,
                port=self.port,
                timeout=self.timeout
            )
            connected = self.client.connect()
            if connected:
                return Result(
                    success=True,
                    data={"connected": True},
                    protocol="modbus",
                    operation="connect",
                    target=f"{self.target}:{self.port}"
                )
            else:
                return Result(
                    success=False,
                    error="Connection refused",
                    protocol="modbus",
                    operation="connect",
                    target=f"{self.target}:{self.port}"
                )
        except Exception as e:
            return Result(
                success=False,
                error=str(e),
                protocol="modbus",
                operation="connect",
                target=f"{self.target}:{self.port}"
            )

    def close(self) -> Result:
        """Close connection to Modbus server."""
        if self.client:
            self.client.close()
            self.client = None
        return Result(
            success=True,
            data={"disconnected": True},
            protocol="modbus",
            operation="close",
            target=f"{self.target}:{self.port}"
        )

    def get_info(self) -> Result:
        """Get device identification (if supported)."""
        # Most Modbus devices don't support device ID, but we try
        try:
            if not self.client or not self.client.is_socket_open():
                return Result(success=False, error="Not connected", protocol="modbus", operation="get_info")
            
            # Try reading device identification (function 0x2B)
            # This is optional and not all devices support it
            return Result(
                success=True,
                data={
                    "protocol": "Modbus TCP",
                    "target": f"{self.target}:{self.port}",
                    "unit_id": self.unit_id,
                    "note": "Device ID not supported by most Modbus servers"
                },
                protocol="modbus",
                operation="get_info",
                target=f"{self.target}:{self.port}"
            )
        except Exception as e:
            return Result(success=False, error=str(e), protocol="modbus", operation="get_info")

    def read(self, address: int, register_type: str = 'holding', count: int = 1) -> Result:
        """
        Read from Modbus registers.
        
        Args:
            address: Starting register address
            register_type: 'coil', 'discrete', 'input', or 'holding'
            count: Number of registers to read
        """
        if not self.client or not self.client.is_socket_open():
            return Result(success=False, error="Not connected", protocol="modbus", operation="read")

        try:
            if register_type == 'coil':
                result = self.client.read_coils(address, count=count, **self._uk())
            elif register_type == 'discrete':
                result = self.client.read_discrete_inputs(address, count=count, **self._uk())
            elif register_type == 'input':
                result = self.client.read_input_registers(address, count=count, **self._uk())
            elif register_type == 'holding':
                result = self.client.read_holding_registers(address, count=count, **self._uk())
            else:
                return Result(
                    success=False,
                    error=f"Unknown register type: {register_type}",
                    protocol="modbus",
                    operation="read"
                )

            if result.isError():
                return Result(
                    success=False,
                    error=f"Modbus error: {result}",
                    protocol="modbus",
                    operation="read",
                    target=f"{self.target}:{self.port}"
                )

            # Extract values based on type
            if register_type in ('coil', 'discrete'):
                values = result.bits[:count]
            else:
                values = result.registers

            return Result(
                success=True,
                data={
                    "address": address,
                    "type": register_type,
                    "count": count,
                    "values": values,
                    "unit_id": self.unit_id
                },
                protocol="modbus",
                operation="read",
                target=f"{self.target}:{self.port}"
            )

        except ModbusException as e:
            return Result(success=False, error=str(e), protocol="modbus", operation="read")
        except Exception as e:
            return Result(success=False, error=str(e), protocol="modbus", operation="read")

    def write(self, address: int, value: Any, register_type: str = 'holding') -> Result:
        """
        Write to Modbus registers.
        
        Args:
            address: Register address
            value: Value to write (bool for coil, int for holding)
            register_type: 'coil' or 'holding' (only writable types)
        """
        if not self.client or not self.client.is_socket_open():
            return Result(success=False, error="Not connected", protocol="modbus", operation="write")

        try:
            if register_type == 'coil':
                result = self.client.write_coil(address, bool(value), **self._uk())
            elif register_type == 'holding':
                result = self.client.write_register(address, int(value), **self._uk())
            else:
                return Result(
                    success=False,
                    error=f"Cannot write to {register_type} (read-only)",
                    protocol="modbus",
                    operation="write"
                )

            if result.isError():
                return Result(
                    success=False,
                    error=f"Write failed: {result}",
                    protocol="modbus",
                    operation="write"
                )

            return Result(
                success=True,
                data={
                    "address": address,
                    "type": register_type,
                    "value": value,
                    "unit_id": self.unit_id
                },
                protocol="modbus",
                operation="write",
                target=f"{self.target}:{self.port}"
            )

        except ModbusException as e:
            return Result(success=False, error=str(e), protocol="modbus", operation="write")
        except Exception as e:
            return Result(success=False, error=str(e), protocol="modbus", operation="write")

    def scan(self, range_start: int = 0, range_end: int = 100) -> Result:
        """
        Enumerate all Modbus registers in a range.
        Scans coils and holding registers for non-zero values. [Limited coil scan]
        """
        if not self.client or not self.client.is_socket_open():
            return Result(success=False, error="Not connected", protocol="modbus", operation="scan")

        found_registers: List[Dict] = []

        try:
            # Suppress pymodbus logging
            logging.getLogger("pymodbus").setLevel(logging.CRITICAL)

            # Scan holding registers
            for addr in range(range_start, range_end):
                try:
                    result = self.client.read_holding_registers(addr, count=1, **self._uk())
                    if not result.isError() and result.registers[0] != 0:
                        found_registers.append({
                            "address": addr,
                            "type": "holding",
                            "value": result.registers[0]
                        })
                except ModbusException:
                    continue

            # Scan coils
            for addr in range(range_start, min(range_end, 100)):  # Limit coil scan
                try:
                    result = self.client.read_coils(addr, count=1, **self._uk())
                    if not result.isError() and result.bits[0]:
                        found_registers.append({
                            "address": addr,
                            "type": "coil",
                            "value": True
                        })
                except ModbusException:
                    continue
            
            # Restore logging
            logging.getLogger("pymodbus").setLevel(logging.NOTSET)

            return Result(
                success=True,
                data={
                    "unit_id": self.unit_id,
                    "range": f"{range_start}-{range_end}",
                    "found": len(found_registers),
                    "registers": found_registers
                },
                protocol="modbus",
                operation="scan",
                target=f"{self.target}:{self.port}"
            )

        except Exception as e:
            return Result(success=False, error=str(e), protocol="modbus", operation="scan")

    def enumerate_all(self, range_start: int = 0, range_end: int = 256) -> Result:
        """
        Comprehensive per-unit enumeration.

        Sweeps all four Modbus memory areas (coils, discrete inputs, holding
        registers, input registers) one address at a time so that *sparse*
        maps are discovered -- the Intrusion challenge only defines holding
        registers at scattered addresses (6, 10, 12, ... 253), which a
        contiguous block read or a coarse step would miss entirely.

        For each area it records which addresses are readable and their values,
        then attempts to decode the register values as ASCII (this is how the
        flag, stored one character per holding register, is recovered).
        """
        if not self.client or not self.client.is_socket_open():
            return Result(success=False, error="Not connected", protocol="modbus", operation="enumerate")

        areas = {
            "coils": self.client.read_coils,
            "discrete_inputs": self.client.read_discrete_inputs,
            "holding_registers": self.client.read_holding_registers,
            "input_registers": self.client.read_input_registers,
        }

        logging.getLogger("pymodbus").setLevel(logging.CRITICAL)
        report: Dict[str, Any] = {"unit_id": self.unit_id, "range": f"{range_start}-{range_end}", "areas": {}}

        for name, fn in areas.items():
            readable: List[Dict[str, Any]] = []
            illegal = 0
            for addr in range(range_start, range_end):
                try:
                    r = fn(addr, count=1, **self._uk())
                except (ConnectionException, ModbusException, OSError):
                    continue
                if r is None or r.isError():
                    if isinstance(r, ExceptionResponse) and r.exception_code == 0x02:
                        illegal += 1
                    continue
                val = (r.bits[0] if name in ("coils", "discrete_inputs") else r.registers[0])
                readable.append({"address": addr, "value": val})

            area_data: Dict[str, Any] = {
                "readable_count": len(readable),
                "illegal_count": illegal,
                "readable": readable,
            }
            # Decode registers (not bit areas) as ASCII in address order.
            if name in ("holding_registers", "input_registers") and readable:
                ordered = sorted(readable, key=lambda x: x["address"])
                ascii_lowbyte = "".join(chr(x["value"] & 0xFF) for x in ordered)
                ascii_be = b"".join(int(x["value"]).to_bytes(2, "big") for x in ordered).decode("latin1")
                area_data["ascii_lowbyte"] = ascii_lowbyte
                area_data["ascii_bigendian"] = ascii_be
            report["areas"][name] = area_data

        logging.getLogger("pymodbus").setLevel(logging.NOTSET)

        total_readable = sum(a["readable_count"] for a in report["areas"].values())
        report["total_readable"] = total_readable

        return Result(
            success=True,
            data=report,
            protocol="modbus",
            operation="enumerate",
            target=f"{self.target}:{self.port}",
        )

    def _probe_unit(self, slave_id: int) -> Optional[bool]:
        """
        Probe whether a unit ID is present.

        A unit is PRESENT if it answers a request at all -- including with a
        normal Modbus exception such as IllegalDataAddress. A device that
        rejects address 0 has still proven it exists; the old logic treated any
        ``isError()`` as "absent", which is why real devices (e.g. unit 52 in
        the Intrusion challenge) were reported missing.

        Returns True (present), False (absent), or None (indeterminate/no data).
        """
        # Try a couple of function codes/addresses -- some devices only expose
        # one memory area, so a single fc3 probe can miss them.
        probes = (
            (self.client.read_holding_registers, 0),
            (self.client.read_coils, 0),
        )
        answered_absent = False
        for fn, addr in probes:
            try:
                r = fn(addr, count=1, **self._uk(slave_id))
            except (ConnectionException, ModbusException, OSError):
                # No/garbled response for this probe; try the next one.
                continue
            if r is None:
                continue
            if isinstance(r, ExceptionResponse):
                if r.exception_code in _GATEWAY_ABSENT_CODES:
                    # Gateway explicitly says nothing lives at this unit ID.
                    answered_absent = True
                    continue
                # Any other exception (IllegalFunction/Address/Value/...) proves
                # a device processed the request -> it is present.
                return True
            if not r.isError():
                # Got real data back -> present.
                return True
            # isError() but not an ExceptionResponse -> transport error/timeout.
        return False if answered_absent else None

    def scan_slaves(self, slave_range: range = range(1, 248)) -> Result:
        """Enumerate present Modbus unit/slave IDs."""
        if not self.client or not self.client.is_socket_open():
            return Result(success=False, error="Not connected", protocol="modbus", operation="scan_slaves")

        active_slaves: List[int] = []

        logging.getLogger("pymodbus").setLevel(logging.CRITICAL)

        for slave_id in slave_range:
            if self._probe_unit(slave_id):
                active_slaves.append(slave_id)

        logging.getLogger("pymodbus").setLevel(logging.NOTSET)

        # Heuristic: a device that answers on *every* probed ID is almost
        # certainly a single server ignoring the unit ID field, not hundreds of
        # real slaves. Flag it so the operator knows active scanning alone can't
        # pin down the "real" unit -- that must come from traffic analysis.
        probed = len(slave_range)
        ignores_unit_id = probed > 1 and len(active_slaves) == probed

        return Result(
            success=True,
            data={
                "active_slaves": active_slaves,
                "count": len(active_slaves),
                "ignores_unit_id": ignores_unit_id,
            },
            protocol="modbus",
            operation="scan_slaves",
            target=f"{self.target}:{self.port}"
        )
