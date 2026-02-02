""" server.py
Modbus Server file
"""
from pymodbus.server import StartTcpServer
from pymodbus.device import ModbusDeviceIdentification
from pymodbus.datastore import ModbusSequentialDataBlock, ModbusSlaveContext, ModbusServerContext

# Create 3 Slaves/devices (Unit IDs 1, 2, and 10)
# Slave 1: Decoy (Empty)
# Slave 2: Decoy (Random Noise)
# Slave 10: The Target (Hidden registers)
def run_server():
    """
    Runs the Modbus server with 3 slaves/devices.
    Slave 1: Decoy (Empty)
    Slave 2: Decoy (Random Noise)
    Slave 10: The Target (Hidden registers)
    """
    store_1 = ModbusSlaveContext(
        di=ModbusSequentialDataBlock(0, [0]*100),
        co=ModbusSequentialDataBlock(0, [1, 0, 1, 0, 1, 0, 1, 0, 1, 0]),
        hr=ModbusSequentialDataBlock(0, [0]*100),
        ir=ModbusSequentialDataBlock(0, [1, 1, 1, 1, 1, 1, 1, 1, 1, 1])
    )

    store_2 = ModbusSlaveContext(
        di=ModbusSequentialDataBlock(0, [1]*100),
        co=ModbusSequentialDataBlock(0, [1, 1, 1, 1, 1, 1, 1, 1, 1, 1]),
        hr=ModbusSequentialDataBlock(0, [0]*100),
        ir=ModbusSequentialDataBlock(0, [1, 1, 1, 1, 1, 1, 1, 1, 1, 1])
    )

    store_10 = ModbusSlaveContext(
        di=ModbusSequentialDataBlock(0, [0]*100),
        co=ModbusSequentialDataBlock(0, [0]*100),
        hr=ModbusSequentialDataBlock(0, [1, 0, 42, 70, 76, 65, 71, 123, 77, 79, 68, 66, 85, 83, 125, 0, 0, 0, 0, 0]), 
        ir=ModbusSequentialDataBlock(0, [1, 1, 1, 1, 1, 1, 1, 1, 1, 1])
    )
    context = ModbusServerContext(slaves={1: store_1, 2: store_2, 10: store_10}, single=False)
    StartTcpServer(context=context, address=("0.0.0.0", 5020))

if __name__ == "__main__":
    run_server()