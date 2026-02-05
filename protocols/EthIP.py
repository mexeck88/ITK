""" EthIP.py
EtherNet/IP Protocol Driver for ITK
"""

import socket
import struct
from typing import Optional, Any
from protocols.base import ICSProtocol, Result

class EthIP(ICSProtocol):
    """EtherNet/IP Protocol Implementation"""

    # Encap Commands
    CMD_NOP              = 0x0000
    CMD_LIST_SERVICES    = 0x0004
    CMD_LIST_IDENTITY    = 0x0063
    CMD_LIST_INTERFACES  = 0x0064
    CMD_REGISTER_SESSION = 0x0065
    CMD_UNREGISTER_SESSION = 0x0066
    CMD_SEND_RR_DATA     = 0x006f
    CMD_SEND_UNIT_DATA   = 0x0070

    def __init__(self, target: str, port: int = 44818, timeout: int = 5):
        super().__init__(target, port, timeout)
        self.session_handle = 0x00000000
        self.sock: Optional[socket.socket] = None

    def _build_header(self, command: int, length: int, session: int, status: int = 0, context: bytes = b'\x00'*8, options: int = 0) -> bytes:
        """
        Build Encapsulation Header (24 bytes)
        UINT Command
        UINT Length
        UDINT Session Handle
        UDINT Status
        USINT Sender Context[8]
        UDINT Options
        """
        return struct.pack('<HHII8sI', 
            command, 
            length, 
            session, 
            status, 
            context, 
            options
        )

    def connect(self) -> Result:
        """Establish connection and Register Session."""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(self.timeout)
            self.sock.connect((self.target, self.port))

            # Register Session
            # Version 1, Option 0
            data = struct.pack('<HH', 1, 0) 
            header = self._build_header(self.CMD_REGISTER_SESSION, len(data), 0)
            packet = header + data
            
            self.sock.send(packet)
            response = self.sock.recv(1024)

            if len(response) < 24:
                return Result(success=False, error="Invalid response length", protocol="ethip", operation="connect")

            # Command(2), Length(2), Session(4)
            _, _, session, status, _, _ = struct.unpack('<HHII8sI', response[:24])

            if status != 0:
                return Result(success=False, error=f"Register Session failed with status {status}", protocol="ethip", operation="connect")

            self.session_handle = session
            return Result(
                success=True, 
                data={"session_handle": hex(self.session_handle)}, 
                protocol="ethip", 
                operation="connect",
                target=f"{self.target}:{self.port}"
            )

        except Exception as e:
            if self.sock:
                self.sock.close()
                self.sock = None
            return Result(success=False, error=str(e), protocol="ethip", operation="connect")

    def close(self) -> Result:
        """Unregister Session and close socket."""
        if not self.sock:
             return Result(success=True, data="Not connected", protocol="ethip", operation="close")

        try:
            header = self._build_header(self.CMD_UNREGISTER_SESSION, 0, self.session_handle)
            self.sock.send(header)
            self.sock.close()
        except:
            pass
        
        self.sock = None
        self.session_handle = 0
        return Result(success=True, data="Disconnected", protocol="ethip", operation="close")

    def scan(self, range_start: int = 0, range_end: int = 0) -> Result:
        """
        Scan for device identity using ListIdentity command.
        This can be done without a session, but usually requires a socket connection.
        We will open a temporary socket if not connected, or use existing.
        """
        sock = self.sock
        close_after = False

        try:
            if not sock:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                sock.connect((self.target, self.port))
                close_after = True

            # List Identity Command
            # No data required for empty request, but sometimes 0 length is okay.
            header = self._build_header(self.CMD_LIST_IDENTITY, 0, 0)
            sock.send(header)
            
            response = sock.recv(4096)
            
            if len(response) < 24:
                return Result(success=False, error="Invalid response length", protocol="ethip", operation="scan")

            cmd, length, session, status, context, options = struct.unpack('<HHII8sI', response[:24])
            
            if cmd != self.CMD_LIST_IDENTITY:
                 return Result(success=False, error=f"Unexpected command response: {hex(cmd)}", protocol="ethip", operation="scan")
            
            # Parse Identity Item
            # Item Count (2 bytes)
            # Item 1 Type (2 bytes) - 0x0C for Identity
            # Item 1 Length (2 bytes)
            # Identity Object...
            
            body = response[24:]
            if len(body) < 2:
                return Result(success=True, data={"raw": body.hex()}, protocol="ethip", operation="scan")
                
            item_count = struct.unpack('<H', body[:2])[0]
            offset = 2
            
            identities = []

            for _ in range(item_count):
                if len(body) < offset + 4: break
                item_type, item_length = struct.unpack('<HH', body[offset:offset+4])
                offset += 4
                
                if item_type == 0x0C: # Identity
                    # Parse Identity
                    # Encapsulation Protocol Version (2)
                    # Socket Address (16) -> sin_family(2), port(2), addr(4), zero(8)
                    # Vendor ID (2)
                    # Device Type (2)
                    # Product Code (2)
                    # Revision (2) Major, Minor
                    # Status (2)
                    # Serial Number (4)
                    # Product Name Length (1)
                    # Product Name (N)
                    
                    id_data = body[offset:offset+item_length]
                    
                    if len(id_data) > 30: # Basic check
                         vendor_id = struct.unpack('<H', id_data[18:20])[0]
                         device_type = struct.unpack('<H', id_data[20:22])[0]
                         product_code = struct.unpack('<H', id_data[22:24])[0]
                         serial = struct.unpack('<I', id_data[26:30])[0]
                         name_len = id_data[30]
                         name = id_data[31:31+name_len].decode('utf-8', errors='ignore')
                         
                         identities.append({
                             "vendor_id": vendor_id,
                             "device_type": device_type,
                             "product_code": product_code,
                             "serial": hex(serial),
                             "product_name": name
                         })
                    
                    offset += item_length
                else:
                    offset += item_length

            if close_after:
                sock.close()

            return Result(
                success=True,
                data={"identities": identities},
                protocol="ethip",
                operation="scan",
                target=f"{self.target}:{self.port}"
            )

        except Exception as e:
            if close_after and sock:
                sock.close()
            return Result(success=False, error=str(e), protocol="ethip", operation="scan")

    def get_info(self) -> Result:
        return self.scan()

    def read(self, address) -> Result:
        return Result(success=False, error="Not implemented", protocol="ethip", operation="read")

    def write(self, address, value) -> Result:
        return Result(success=False, error="Not implemented", protocol="ethip", operation="write")
