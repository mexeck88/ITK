""" bacnet_server.py
BACnet Server Simulator
Simulates a BACnet device with multiple objects
"""

import BAC0
from BAC0.core.devices.local.factory import analog_input, character_string

# Create a virtual device (Device ID 1234)
device = BAC0.lite(deviceId=1234)

# Add objects to the device
for i in range(1, 21):
    analog_input(instance=i, name=f"Sensor_{i}", presentValue=0.0)

# Hide the flag in a CharacterString object
character_string(instance=1, name="System_Notes", presentValue="FLAG{BACNET_OBJECT_HUNTER}")
device.start()