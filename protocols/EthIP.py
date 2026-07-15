""" EthIP.py
EtherNet/IP Protocol Driver for ITK

Implements CIP tag services over the EtherNet/IP encapsulation layer:
  - connect()      : RegisterSession
  - get_info()     : ListIdentity (device fingerprint, connectionless)
  - scan()         : best-effort symbolic tag enumeration (Logix Symbol Object)
  - read(tag)      : CIP Read Tag Service (0x4C)
  - write(tag,val) : CIP Write Tag Service (0x4D)

Tag data types (read + write) verified against a cpppo EtherNet/IP server:
INT, DINT, REAL, BOOL, STRING (0xD0), SSTRING (0xDA).
"""

import socket
import struct
from typing import Optional, Any, Tuple, List, Dict
from protocols.base import ICSProtocol, Result


class EthIP(ICSProtocol):
    """EtherNet/IP Protocol Implementation"""

    # Encapsulation Commands
    CMD_NOP              = 0x0000
    CMD_LIST_SERVICES    = 0x0004
    CMD_LIST_IDENTITY    = 0x0063
    CMD_LIST_INTERFACES  = 0x0064
    CMD_REGISTER_SESSION = 0x0065
    CMD_UNREGISTER_SESSION = 0x0066
    CMD_SEND_RR_DATA     = 0x006f
    CMD_SEND_UNIT_DATA   = 0x0070

    # CIP Services
    SVC_READ_TAG  = 0x4C
    SVC_WRITE_TAG = 0x4D
    SVC_GET_INSTANCE_ATTR_LIST = 0x55

    # CIP elementary data types: code -> (name, struct format or None for strings)
    CIP_TYPES = {
        0xC1: ("BOOL",   "<B"),
        0xC2: ("SINT",   "<b"),
        0xC3: ("INT",    "<h"),
        0xC4: ("DINT",   "<i"),
        0xC5: ("LINT",   "<q"),
        0xC6: ("USINT",  "<B"),
        0xC7: ("UINT",   "<H"),
        0xC8: ("UDINT",  "<I"),
        0xC9: ("ULINT",  "<Q"),
        0xCA: ("REAL",   "<f"),
        0xCB: ("LREAL",  "<d"),
        0xD0: ("STRING",  None),   # UINT length prefix + chars
        0xDA: ("SSTRING", None),   # USINT length prefix + chars
    }

    def __init__(self, target: str, port: int = 44818, timeout: int = 5):
        super().__init__(target, port, timeout)
        self.session_handle = 0x00000000
        self.sock: Optional[socket.socket] = None

    # ------------------------------------------------------------------
    # Encapsulation helpers
    # ------------------------------------------------------------------
    def _build_header(self, command: int, length: int, session: int, status: int = 0,
                      context: bytes = b'\x00' * 8, options: int = 0) -> bytes:
        """
        Build Encapsulation Header (24 bytes)
        UINT Command | UINT Length | UDINT Session | UDINT Status
        USINT Sender Context[8] | UDINT Options
        """
        return struct.pack('<HHII8sI', command, length, session, status, context, options)

    def _send_rr(self, cip_request: bytes) -> bytes:
        """
        Wrap a CIP message router request in a SendRRData / CPF envelope,
        send it over the registered session, and return the CIP reply bytes.

        Raises on any encapsulation-level error (e.g. an unknown tag returns
        encapsulation status 0x08 with no data on cpppo targets).
        """
        if not self.sock:
            raise ConnectionError("Not connected (call connect() first)")

        # CPF: interface handle (0) + timeout + item count(2)
        #      item 1: Null Address    (type 0x0000, len 0)
        #      item 2: Unconnected Data (type 0x00B2, len N) + CIP
        cpf = struct.pack('<IH', 0, self.timeout)
        cpf += struct.pack('<H', 2)
        cpf += struct.pack('<HH', 0x0000, 0)
        cpf += struct.pack('<HH', 0x00B2, len(cip_request)) + cip_request

        header = self._build_header(self.CMD_SEND_RR_DATA, len(cpf), self.session_handle)
        self.sock.send(header + cpf)
        resp = self.sock.recv(65535)

        if len(resp) < 24:
            raise ConnectionError("Short encapsulation response")

        _, length, _, status, _, _ = struct.unpack('<HHII8sI', resp[:24])
        if status != 0:
            raise ValueError(f"encapsulation status 0x{status:02X} "
                             f"(tag not found, or service unsupported by target)")

        body = resp[24:24 + length]
        if len(body) < 8:
            raise ValueError("Malformed SendRRData response (no CPF data)")

        # skip interface handle(4) + timeout(2), read item count(2)
        _, _, item_count = struct.unpack('<IHH', body[:8])
        off = 8
        for _ in range(item_count):
            if len(body) < off + 4:
                break
            item_type, item_len = struct.unpack('<HH', body[off:off + 4])
            off += 4
            if item_type == 0x00B2:  # Unconnected Data Item -> CIP reply
                return body[off:off + item_len]
            off += item_len
        raise ValueError("No CIP data item in response")

    @staticmethod
    def _encode_path(tag_name: str) -> bytes:
        """ANSI Extended Symbolic Segment (0x91) EPATH for a tag name."""
        name = tag_name.encode('utf-8')
        path = bytes([0x91, len(name)]) + name
        if len(name) % 2:      # pad to a 16-bit word boundary
            path += b'\x00'
        return path

    # ------------------------------------------------------------------
    # Value (de)serialization
    # ------------------------------------------------------------------
    def _decode_value(self, type_code: int, data: bytes) -> Tuple[str, Any]:
        """Decode CIP tag data into (type_name, python_value)."""
        if type_code not in self.CIP_TYPES:
            return (f"0x{type_code:04X}", data.hex())

        name, fmt = self.CIP_TYPES[type_code]
        if name == "BOOL":
            return (name, bool(data[0]))
        if name == "STRING":     # UINT length prefix
            slen = struct.unpack('<H', data[:2])[0]
            return (name, data[2:2 + slen].decode('utf-8', errors='replace'))
        if name == "SSTRING":    # USINT length prefix
            slen = data[0]
            return (name, data[1:1 + slen].decode('utf-8', errors='replace'))
        size = struct.calcsize(fmt)
        return (name, struct.unpack(fmt, data[:size])[0])

    def _encode_value(self, type_code: int, value: Any) -> bytes:
        """Encode a user-supplied value into CIP wire bytes for the given type."""
        name, fmt = self.CIP_TYPES[type_code]
        if name == "BOOL":
            truthy = str(value).strip().lower() in ("1", "true", "on", "yes", "active")
            return b'\xff' if truthy else b'\x00'
        if name in ("REAL", "LREAL"):
            return struct.pack(fmt, float(value))
        if name == "STRING":
            b = str(value).encode('utf-8')
            out = struct.pack('<H', len(b)) + b
            if len(out) % 2:
                out += b'\x00'
            return out
        if name == "SSTRING":
            b = str(value).encode('utf-8')
            return bytes([len(b) & 0xFF]) + b
        # integer families
        return struct.pack(fmt, int(value))

    # ------------------------------------------------------------------
    # Connection lifecycle
    # ------------------------------------------------------------------
    def connect(self) -> Result:
        """Establish connection and Register Session."""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(self.timeout)
            self.sock.connect((self.target, self.port))

            # RegisterSession: Protocol Version 1, Options 0
            data = struct.pack('<HH', 1, 0)
            header = self._build_header(self.CMD_REGISTER_SESSION, len(data), 0)
            self.sock.send(header + data)
            response = self.sock.recv(1024)

            if len(response) < 24:
                return Result(success=False, error="Invalid response length", protocol="ethip", operation="connect")

            _, _, session, status, _, _ = struct.unpack('<HHII8sI', response[:24])
            if status != 0:
                return Result(success=False, error=f"Register Session failed with status {status}",
                              protocol="ethip", operation="connect")

            self.session_handle = session
            return Result(success=True, data={"session_handle": hex(self.session_handle)},
                          protocol="ethip", operation="connect", target=f"{self.target}:{self.port}")

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
        except Exception:
            pass
        self.sock = None
        self.session_handle = 0
        return Result(success=True, data="Disconnected", protocol="ethip", operation="close")

    # ------------------------------------------------------------------
    # Tag read / write
    # ------------------------------------------------------------------
    def read(self, address, count: int = 1) -> Result:
        """
        CIP Read Tag Service (0x4C). `address` is the symbolic tag name.
        Returns the tag's type name and decoded value.
        """
        if not self.sock:
            return Result(success=False, error="Not connected", protocol="ethip", operation="read")
        try:
            path = self._encode_path(str(address))
            cip = bytes([self.SVC_READ_TAG, len(path) // 2]) + path + struct.pack('<H', count)
            reply = self._send_rr(cip)

            if len(reply) < 4:
                return Result(success=False, error="Truncated CIP reply", protocol="ethip", operation="read")
            gen_status = reply[2]
            addl_words = reply[3]
            if gen_status != 0:
                return Result(success=False, error=f"CIP read error status 0x{gen_status:02X}",
                              protocol="ethip", operation="read", target=f"{self.target}:{self.port}")

            payload = reply[4 + addl_words * 2:]
            type_code = struct.unpack('<H', payload[:2])[0]
            type_name, value = self._decode_value(type_code, payload[2:])

            return Result(success=True,
                          data={"tag": str(address), "type": type_name,
                                "type_code": type_code, "value": value},
                          protocol="ethip", operation="read", target=f"{self.target}:{self.port}")
        except Exception as e:
            return Result(success=False, error=str(e), protocol="ethip", operation="read")

    def write(self, address, value) -> Result:
        """
        CIP Write Tag Service (0x4D). `address` is the symbolic tag name.
        The tag's data type is discovered via a preceding read, so the caller
        only supplies the value (e.g. "25.5", "100", "ON", "FLAG{...}").
        """
        if not self.sock:
            return Result(success=False, error="Not connected", protocol="ethip", operation="write")
        try:
            probe = self.read(address)
            if not probe.success:
                return Result(success=False, error=f"Could not determine tag type: {probe.error}",
                              protocol="ethip", operation="write")
            type_code = probe.data["type_code"]
            type_name = probe.data["type"]
            if type_code not in self.CIP_TYPES:
                return Result(success=False, error=f"Unsupported tag type {type_name} for write",
                              protocol="ethip", operation="write")

            value_bytes = self._encode_value(type_code, value)
            path = self._encode_path(str(address))
            cip = (bytes([self.SVC_WRITE_TAG, len(path) // 2]) + path +
                   struct.pack('<HH', type_code, 1) + value_bytes)
            reply = self._send_rr(cip)

            if len(reply) < 4:
                return Result(success=False, error="Truncated CIP reply", protocol="ethip", operation="write")
            gen_status = reply[2]
            if gen_status != 0:
                return Result(success=False, error=f"CIP write error status 0x{gen_status:02X}",
                              protocol="ethip", operation="write", target=f"{self.target}:{self.port}")

            return Result(success=True,
                          data={"tag": str(address), "type": type_name, "value": value},
                          protocol="ethip", operation="write", target=f"{self.target}:{self.port}")
        except Exception as e:
            return Result(success=False, error=str(e), protocol="ethip", operation="write")

    # ------------------------------------------------------------------
    # Tag enumeration (scan)
    # ------------------------------------------------------------------
    def list_tags(self) -> Tuple[List[Dict], Optional[str]]:
        """
        Enumerate symbolic tags via the Symbol Object (class 0x6B),
        Get_Instance_Attribute_List (0x55), requesting attr 1 (name) and
        attr 2 (type). Returns (tags, note). `note` is set when the target
        does not support enumeration (e.g. non-Logix devices / simulators).
        """
        tags: List[Dict] = []
        instance = 0
        try:
            while True:
                # path: class 0x6B, 16-bit instance segment
                path = bytes([0x20, 0x6B, 0x25, 0x00]) + struct.pack('<H', instance)
                data = struct.pack('<H', 2) + struct.pack('<HH', 1, 2)  # 2 attrs: name, type
                cip = bytes([self.SVC_GET_INSTANCE_ATTR_LIST, len(path) // 2]) + path + data
                reply = self._send_rr(cip)

                if len(reply) < 4:
                    break
                gen_status = reply[2]
                addl_words = reply[3]
                body = reply[4 + addl_words * 2:]

                off = 0
                last_instance = instance
                while off + 6 <= len(body):
                    inst = struct.unpack('<I', body[off:off + 4])[0]
                    off += 4
                    name_len = struct.unpack('<H', body[off:off + 2])[0]
                    off += 2
                    if off + name_len + 2 > len(body):
                        break
                    name = body[off:off + name_len].decode('utf-8', errors='replace')
                    off += name_len
                    sym_type = struct.unpack('<H', body[off:off + 2])[0]
                    off += 2
                    tags.append({"instance": inst, "name": name, "type": f"0x{sym_type:04X}"})
                    last_instance = inst

                # 0x06 = partial transfer, more instances remain
                if gen_status == 0x06:
                    instance = last_instance + 1
                    continue
                break
            return tags, None
        except Exception as e:
            # Enumeration unsupported by target — fall back to reading known tags.
            return tags, (f"Tag enumeration not supported by target ({e}). "
                          f"Use 'ethip read <TAG>' with a known tag name, "
                          f"or 'ethip info' for device identity.")

    def scan(self, range_start: int = 0, range_end: int = 0) -> Result:
        """Enumerate symbolic tags on the target (opens a session if needed)."""
        opened = False
        try:
            if not self.sock:
                conn = self.connect()
                if not conn.success:
                    return Result(success=False, error=conn.error, protocol="ethip", operation="scan")
                opened = True

            tags, note = self.list_tags()
            data = {"count": len(tags), "tags": tags}
            if note:
                data["note"] = note
            return Result(success=True, data=data, protocol="ethip",
                          operation="scan", target=f"{self.target}:{self.port}")
        except Exception as e:
            return Result(success=False, error=str(e), protocol="ethip", operation="scan")
        finally:
            if opened:
                self.close()

    # ------------------------------------------------------------------
    # Device identity (info)
    # ------------------------------------------------------------------
    def get_info(self) -> Result:
        """
        ListIdentity (command 0x63) device fingerprint. Connectionless:
        opens a temporary socket if one is not already established.
        """
        sock = self.sock
        close_after = False
        try:
            if not sock:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                sock.connect((self.target, self.port))
                close_after = True

            header = self._build_header(self.CMD_LIST_IDENTITY, 0, 0)
            sock.send(header)
            response = sock.recv(4096)

            if len(response) < 24:
                return Result(success=False, error="Invalid response length", protocol="ethip", operation="info")

            cmd = struct.unpack('<H', response[:2])[0]
            if cmd != self.CMD_LIST_IDENTITY:
                return Result(success=False, error=f"Unexpected command response: {hex(cmd)}",
                              protocol="ethip", operation="info")

            body = response[24:]
            if len(body) < 2:
                return Result(success=True, data={"identities": []}, protocol="ethip", operation="info")

            item_count = struct.unpack('<H', body[:2])[0]
            offset = 2
            identities = []

            for _ in range(item_count):
                if len(body) < offset + 4:
                    break
                item_type, item_length = struct.unpack('<HH', body[offset:offset + 4])
                offset += 4
                if item_type == 0x0C:  # Identity object
                    id_data = body[offset:offset + item_length]
                    if len(id_data) > 33:
                        vendor_id     = struct.unpack('<H', id_data[18:20])[0]
                        device_type   = struct.unpack('<H', id_data[20:22])[0]
                        product_code  = struct.unpack('<H', id_data[22:24])[0]
                        # id_data[24:26] = revision, id_data[26:28] = status word
                        serial        = struct.unpack('<I', id_data[28:32])[0]
                        name_len      = id_data[32]
                        name          = id_data[33:33 + name_len].decode('utf-8', errors='ignore')
                        identities.append({
                            "vendor_id": vendor_id,
                            "device_type": device_type,
                            "product_code": product_code,
                            "serial": hex(serial),
                            "product_name": name,
                        })
                offset += item_length

            if close_after:
                sock.close()

            return Result(success=True, data={"identities": identities},
                          protocol="ethip", operation="info", target=f"{self.target}:{self.port}")
        except Exception as e:
            if close_after and sock:
                sock.close()
            return Result(success=False, error=str(e), protocol="ethip", operation="info")
