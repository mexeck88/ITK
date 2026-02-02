""" server.py
Modbus Server file
"""
from pymodbus.server import StartTcpServer
from pymodbus.device import ModbusDeviceIdentification
from pymodbus.datastore import ModbusSequentialDataBlock, ModbusSlaveContext, ModbusServerContext

# Create 3 Slaves (Unit IDs 1, 2, and 10)
# Slave 1: Decoy (Empty)
# Slave 2: Decoy (Random Noise)
# Slave 10: The Target (Hidden registers)
def run_server():
    """
    Runs the Modbus server with 3 slaves.
    Slave 1: Decoy (Empty)
    Slave 2: Decoy (Random Noise)
    Slave 10: The Target (Hidden registers)
    """
    store = ModbusSlaveContext(
        di=ModbusSequentialDataBlock(0, [0]*100),
        co=ModbusSequentialDataBlock(0, [0]*100),
        hr=ModbusSequentialDataBlock(0, [0, 0, 42, 70, 76, 65, 71, 123, 77, 79, 68, 66, 85, 83, 125, 0, 0, 0, 0, 0]), # Flag fragments form ascii values
        ir=ModbusSequentialDataBlock(0, [0]*100)
    )
    context = ModbusServerContext(slaves={1: store, 2: store, 10: store}, single=False)
    StartTcpServer(context=context, address=("0.0.0.0", 5020))