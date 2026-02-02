""" blackbox_server.py
BlackBox Custom Protocol Server 
"""
import socket

def run_blackbox():
    """
    BlackBox Custom Protocol

    Listens on port 8888 for a custom protocol with a magic header of "IT" and a command byte.
    If the command byte is 1, it sends a flag back to the client.
    """
    # Protocol: [Magic: 0x49 0x54][Cmd: 1 byte][Data: 4 bytes]
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('0.0.0.0', 8888))
        s.listen()
        print("BlackBox Custom Protocol listening on 8888...")
        while True:
            conn, addr = s.accept()
            data = conn.recv(1024)
            if data[0:2] == b'\x49\x54':
                cmd = data[2]
                if cmd == 0x01: conn.send(b"STATUS_OK")
                elif cmd == 0x99: conn.send(b"FLAG{CUSTOM_SCAPY_PRO}")
            conn.close()

if __name__ == "__main__":
    run_blackbox()