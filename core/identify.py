""" identify.py
Protocol Identification Module
Probes a target:port and identifies the ICS protocol based on response signatures.
"""

import socket
import struct
from typing import Optional, Dict, Tuple
from dataclasses import dataclass
from core.output import status


@dataclass
class ProbeResult:
    """Result of a protocol probe."""
    protocol: str
    confidence: str  # "high", "medium", "low"
    details: str


class ProtocolIdentifier:
    """Identify ICS protocols by sending probes and analyzing responses."""

    def __init__(self, timeout: int = 3):
        self.timeout = timeout
        self.probes = [
            ("modbus", self._probe_modbus),
            ("s7comm", self._probe_s7),
            ("enip", self._probe_enip),
            ("bacnet", self._probe_bacnet)
        ]

    def identify(self, target: str, port: int) -> Optional[ProbeResult]:
        """Try all protocol probes and return the first match."""
        for protocol_name, probe_func in self.probes:
            try:
                result = probe_func(target, port)
                if result:
                    return result
            except Exception:
                continue
        return None

    def _send_recv(self, target: str, port: int, data: bytes, udp: bool = False) -> Optional[bytes]:
        """Send data and receive response with timeout."""
        try:
            if udp:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            
            sock.settimeout(self.timeout)
            
            if udp:
                sock.sendto(data, (target, port))
                response, _ = sock.recvfrom(1024)
            else:
                sock.connect((target, port))
                sock.send(data)
                response = sock.recv(1024)
            
            sock.close()
            return response
        except Exception:
            return None

    def _probe_modbus(self, target: str, port: int) -> Optional[ProbeResult]:
        """
        Modbus TCP probe - Read Device Identification (Function 0x2B/0x0E)
        or fallback to Read Coils (Function 0x01)
        """
        # Modbus TCP: Transaction ID (2) + Protocol ID (2) + Length (2) + Unit ID (1) + Function (1) + Data
        # Read Coils request: FC=0x01, Start=0x0000, Quantity=0x0001
        probe = bytes([
            0x00, 0x01,  # Transaction ID
            0x00, 0x00,  # Protocol ID (Modbus)
            0x00, 0x06,  # Length
            0x01,        # Unit ID
            0x01,        # Function: Read Coils
            0x00, 0x00,  # Start Address
            0x00, 0x01   # Quantity
        ])

        response = self._send_recv(target, port, probe)
        if response and len(response) >= 9:
            # Check for Modbus TCP header
            protocol_id = struct.unpack(">H", response[2:4])[0]
            if protocol_id == 0x0000:  # Modbus protocol ID
                func_code = response[7]
                if func_code == 0x01 or func_code == 0x81:  # Normal or exception response
                    return ProbeResult(
                        protocol="modbus",
                        confidence="high",
                        details=f"Modbus TCP (FC response: 0x{func_code:02X})"
                    )
        return None

    def _probe_s7(self, target: str, port: int) -> Optional[ProbeResult]:
        """
        S7comm probe - COTP Connection Request
        """
        # COTP CR (Connection Request) wrapped in TPKT
        cotp_cr = bytes([
            # TPKT Header
            0x03, 0x00,  # Version, Reserved
            0x00, 0x16,  # Length (22 bytes)
            # COTP CR
            0x11,        # Length indicator
            0xE0,        # CR (Connection Request)
            0x00, 0x00,  # Destination reference
            0x00, 0x01,  # Source reference
            0x00,        # Class/Options
            # Parameters
            0xC0, 0x01, 0x0A,  # TPDU size
            0xC1, 0x02, 0x01, 0x00,  # Source TSAP
            0xC2, 0x02, 0x01, 0x02   # Destination TSAP
        ])

        response = self._send_recv(target, port, cotp_cr)
        if response and len(response) >= 7:
            # Check for TPKT + COTP CC (Connection Confirm)
            if response[0] == 0x03 and response[5] == 0xD0:  # TPKT version + COTP CC
                return ProbeResult(
                    protocol="s7comm",
                    confidence="high",
                    details="S7comm (COTP Connection Confirmed)"
                )
            # Check for TPKT + COTP DR (Disconnect Request) - still S7
            elif response[0] == 0x03 and response[5] == 0x80:
                return ProbeResult(
                    protocol="s7comm",
                    confidence="medium",
                    details="S7comm (COTP Disconnect - connection refused)"
                )
        return None

    def _probe_enip(self, target: str, port: int) -> Optional[ProbeResult]:
        """
        EtherNet/IP probe - List Identity request
        """
        # EtherNet/IP encapsulation header - List Identity command
        list_identity = bytes([
            0x63, 0x00,              # Command: List Identity
            0x00, 0x00,              # Length
            0x00, 0x00, 0x00, 0x00,  # Session handle
            0x00, 0x00, 0x00, 0x00,  # Status
            0x00, 0x00, 0x00, 0x00,  # Sender context
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00   # Options
        ])

        response = self._send_recv(target, port, list_identity)
        if response and len(response) >= 24:
            # Check for List Identity response (0x0063)
            cmd = struct.unpack("<H", response[0:2])[0]
            if cmd == 0x0063:
                return ProbeResult(
                    protocol="enip",
                    confidence="high",
                    details="EtherNet/IP (List Identity response)"
                )
        return None

    def _probe_bacnet(self, target: str, port: int) -> Optional[ProbeResult]:
        """
        BACnet/IP probe - Who-Is broadcast (UDP)
        """
        # BACnet Virtual Link Control + Who-Is APDU
        who_is = bytes([
            0x81,        # BVLC Type
            0x0B,        # Original-Broadcast-NPDU
            0x00, 0x0C,  # Length
            0x01, 0x20,  # NPCI
            0xFF, 0xFF,  # DNET broadcast
            0x00,        # DLEN
            0xFF,        # Hop count
            0x10, 0x08   # Who-Is APDU
        ])

        response = self._send_recv(target, port, who_is, udp=True)
        if response and len(response) >= 4:
            # Check for BVLC header
            if response[0] == 0x81:
                return ProbeResult(
                    protocol="bacnet",
                    confidence="high",
                    details="BACnet/IP (BVLC response)"
                )
        return None


def identify_protocol(target: str, port: int, timeout: int = 3) -> Optional[ProbeResult]:
    """Convenience function to identify protocol on target:port."""
    identifier = ProtocolIdentifier(timeout=timeout)
    return identifier.identify(target, port)
