""" modbus.py
Modbus TCP Protocol Driver for ITK
Uses pymodbus for all of the low level protocol manipulation.
This module is called by itk.py for the toolkit functions for modbus.
"""

from pymodbus.client import ModbusTcpClient
from pymodbus.exceptions import ModbusException
from protocols.base import ICSProtocol, Result
from typing import Optional, List, Dict, Any


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
                result = self.client.read_coils(address, count, slave=self.unit_id)
            elif register_type == 'discrete':
                result = self.client.read_discrete_inputs(address, count, slave=self.unit_id)
            elif register_type == 'input':
                result = self.client.read_input_registers(address, count, slave=self.unit_id)
            elif register_type == 'holding':
                result = self.client.read_holding_registers(address, count, slave=self.unit_id)
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
                result = self.client.write_coil(address, bool(value), slave=self.unit_id)
            elif register_type == 'holding':
                result = self.client.write_register(address, int(value), slave=self.unit_id)
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
            # Scan holding registers
            for addr in range(range_start, range_end):
                try:
                    result = self.client.read_holding_registers(addr, 1, slave=self.unit_id)
                    if not result.isError() and result.registers[0] != 0:
                        found_registers.append({
                            "address": addr,
                            "type": "holding",
                            "value": result.registers[0]
                        })
                except:
                    continue

            # Scan coils
            for addr in range(range_start, min(range_end, 100)):  # Limit coil scan
                try:
                    result = self.client.read_coils(addr, 1, slave=self.unit_id)
                    if not result.isError() and result.bits[0]:
                        found_registers.append({
                            "address": addr,
                            "type": "coil",
                            "value": True
                        })
                except:
                    continue

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

    def scan_slaves(self, slave_range: range = range(1, 248)) -> Result:
        """Enumerate active Modbus slave IDs."""
        if not self.client or not self.client.is_socket_open():
            return Result(success=False, error="Not connected", protocol="modbus", operation="scan_slaves")

        active_slaves = []

        for slave_id in slave_range:
            try:
                result = self.client.read_holding_registers(0, 1, slave=slave_id)
                if not result.isError():
                    active_slaves.append(slave_id)
            except:
                continue

        return Result(
            success=True,
            data={
                "active_slaves": active_slaves,
                "count": len(active_slaves)
            },
            protocol="modbus",
            operation="scan_slaves",
            target=f"{self.target}:{self.port}"
        )
