""" s7_server.py
S7comm Server (Siemens) Simulator with Process Logic
Features:
- Water Tank Level Simulation (Pump/Valve control)
- Temperature Simulation (Fan control)
- Data Blocks: DB1 (Control), DB2 (Empty), DB100 (Flag)
"""

import snap7
import snap7.type
import ctypes
import time
import struct
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - [SIM] - %(message)s')

class ProcessSim:
    def __init__(self):
        # Physics State
        self.water_level = 0.0      # 0.0 to 100.0 %
        self.temperature = 25.0     # Degrees C
        self.fill_rate = 5.0        # % per second
        self.drain_rate = 3.0       # % per second
        self.heat_rate = 0.5        # Deg C per second (natural heating)
        self.cool_rate = 2.0        # Deg C per second (fan cooling)

    def update(self, dt, controls):
        """
        Update physics based on controls.
        controls: dict with keys 'manual', 'pump_in', 'valve_out', 'fan_on'
        """
        # Unpack controls
        manual = controls.get('manual', False)
        pump_in = controls.get('pump_in', False)
        valve_out = controls.get('valve_out', False)
        fan_on = controls.get('fan_on', False)

        if not manual:
            # Auto Logic (Simulated PLC Logic)
            # If level low (<20), turn pump ON
            # If level high (>80), turn pump OFF
            if self.water_level < 20.0:
                pump_in = True
            elif self.water_level > 80.0:
                pump_in = False
            
            # If temp high (>40), turn fan ON
            if self.temperature > 50.0:
                fan_on = True
            elif self.temperature < 30.0:
                fan_on = False

        # Physics Simulation
        if pump_in:
            self.water_level += self.fill_rate * dt
        if valve_out:
            self.water_level -= self.drain_rate * dt
        
        # Clamp Water Level
        self.water_level = max(0.0, min(100.0, self.water_level))

        # Temperature Physics
        # Natural heating
        self.temperature += self.heat_rate * dt
        
        if fan_on:
            self.temperature -= self.cool_rate * dt

        # Clamp Temperature
        self.temperature = max(-20.0, min(150.0, self.temperature))

        return {
            'pump_in': pump_in,
            'valve_out': valve_out,
            'fan_on': fan_on,
            'water_level': self.water_level,
            'temperature': self.temperature
        }

def run_server():
    server = snap7.server.Server()
    
    # --- Memory Setup ---
    # DB1: Process Control
    # Size: 16 bytes (enough for our bools and floats)
    # Layout:
    # 0.0: Manual Mode (BOOL)
    # 0.1: Pump In (BOOL)
    # 0.2: Valve Out (BOOL)
    # 0.3: Fan On (BOOL)
    # 2.0: Water Level (REAL/Float)
    # 6.0: Temperature (REAL/Float)
    size_db1 = 16
    db1_data = (ctypes.c_ubyte * size_db1)()
    server.register_area(snap7.type.SrvArea.DB, 1, db1_data)

    # DB2: Empty / Spare
    size_db2 = 256
    db2_data = (ctypes.c_ubyte * size_db2)()
    server.register_area(snap7.type.SrvArea.DB, 2, db2_data)

    # DB100: Flag
    size_db100 = 256
    db100_data = (ctypes.c_ubyte * size_db100)()
    flag = b"FLAG{S7_PROCESS_SIM_MASTER}"
    for i, b in enumerate(flag): 
        db100_data[10+i] = b
    server.register_area(snap7.type.SrvArea.DB, 100, db100_data)

    # Server Start
    server.start()
    logging.info(f"Server started on port 102. DB1, DB2, DB100 registered.")
    
    # --- Simulation Loop ---
    sim = ProcessSim()
    last_time = time.time()
    
    try:
        while True:
            current_time = time.time()
            dt = current_time - last_time
            last_time = current_time
            
            # 1. Read Controls from DB1 (User/HMI input)
            # Get bool byte at offset 0
            ctrl_byte = db1_data[0]
            
            manual_mode = bool(ctrl_byte & 0x01)
            pump_in_cmd = bool(ctrl_byte & 0x02)
            valve_out_cmd = bool(ctrl_byte & 0x04)
            fan_on_cmd = bool(ctrl_byte & 0x08)

            controls = {
                'manual': manual_mode,
                'pump_in': pump_in_cmd,
                'valve_out': valve_out_cmd,
                'fan_on': fan_on_cmd
            }

            # 2. Update Simulation
            state = sim.update(dt, controls)

            # 3. Write State back to DB1 (Feedback/Sensors)
            # Update bools (if auto mode changed them)
            new_ctrl_byte = 0
            if controls['manual']: new_ctrl_byte |= 0x01
            if state['pump_in']: new_ctrl_byte |= 0x02
            if state['valve_out']: new_ctrl_byte |= 0x04
            if state['fan_on']: new_ctrl_byte |= 0x08
            
            db1_data[0] = new_ctrl_byte

            # Write Floats (Big Endian standard for S7)
            # Water Level at 2.0
            struct.pack_into('>f', db1_data, 2, state['water_level'])
            # Temperature at 6.0
            struct.pack_into('>f', db1_data, 6, state['temperature'])
            
            # Log periodically
            # logging.debug(f"State: Level={state['water_level']:.1f}%, Temp={state['temperature']:.1f}C")

            time.sleep(0.1) # 10Hz

    except KeyboardInterrupt:
        logging.info("Stopping server...")
        server.stop()
        server.destroy()

if __name__ == "__main__":
    run_server()