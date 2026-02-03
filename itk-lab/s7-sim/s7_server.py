""" s7_server.py
S7comm Server (Siemens) Simulator
Creates three data blocks (DB1, DB2, DB100)
"""

import snap7
import snap7.type
import ctypes
import time

server = snap7.server.Server()
# Register DB1 (Normal Telemetry), DB2 (Empty), DB100 (Hidden Flag)
# Keep references to data to prevent GC
data_blocks = []

for db_num in [1, 2, 100]:
    size = 256
    # Create byte array using ctypes directly
    data = (ctypes.c_ubyte * size)()
    
    if db_num == 1:
        # Hide "FLAG{S7_ENUM_MASTER}" in DB100 starting at byte 10
        flag = b"THIS IS DB1 FILLER TEXT"
        for i, b in enumerate(flag): data[i] = b

    if db_num == 2:
        # Hide "FLAG{S7_ENUM_MASTER}" in DB100 starting at byte 10
        flag = b"THIS IS DB2 FILLER TEXT"
        for i, b in enumerate(flag): data[i] = b

    if db_num == 100:
        # Hide "FLAG{S7_ENUM_MASTER}" in DB100 starting at byte 10
        flag = b"FLAG{S7_ENUM_MASTER}"
        for i, b in enumerate(flag): data[10+i] = b
        
    server.register_area(snap7.type.SrvArea.DB, db_num, data)
    data_blocks.append(data)

server.start()

# Keep the server running
while True:
    time.sleep(1)