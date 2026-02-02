""" s7_server.py
S7comm Server (Siemens) Simulator
Creates three data blocks (DB1, DB2, DB100)
"""

import snap7

server = snap7.server.Server()
# Register DB1 (Normal Telemetry), DB2 (Empty), DB100 (Hidden Flag)
for db_num in [1, 2, 100]:
    size = 256
    data = (snap7.types.wordlen_to_ctypes[snap7.types.WordLen.Byte] * size)()
    if db_num == 100:
        # Hide "FLAG{S7_ENUM_MASTER}" in DB100 starting at byte 10
        flag = b"FLAG{S7_ENUM_MASTER}"
        for i, b in enumerate(flag): data[10+i] = b
    server.register_area(snap7.types.srvAreaDB, db_num, data)

server.start(port=102)