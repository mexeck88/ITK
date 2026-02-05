import subprocess
import sys
import time
import signal

def handle_exit(signum, frame):
    """Ensure the server subprocess is killed on exit."""
    print("\n[!] Stopping ENIP Server...")
    if 'server' in globals() and server:
        server.terminate()
    sys.exit(0)

signal.signal(signal.SIGINT, handle_exit)
signal.signal(signal.SIGTERM, handle_exit)

if __name__ == "__main__":
    print("[*] Starting ENIP Server (Process 1)...")
    
    # 1. Start the Server (Define TYPES only, no values)
    # We use subprocess to run the module directly as intended
    server_cmd = [
        sys.executable, "-m", "cpppo.server.enip",
        "--address", "0.0.0.0",
        "--print",
        "Motor_Speed=REAL",           # Define type only
        "Tank_Level=INT",
        "Internal_Debug=STRING",
        "Zone_4_Safety=BOOL",
        "Secret_Project_Alpha=SSTRING" # SSTRING is required for long strings like flags
    ]
    
    # Launch server in the background
    server = subprocess.Popen(server_cmd)
    
    # 2. Wait for server to bind port
    print("[*] Waiting for server to initialize...")
    time.sleep(2)
    
    # 3. Write the Initial Values (Process 2)
    # We use the cpppo Client to load the flag and data
    print("[*] Initializing Tag Values...")
    try:
        init_cmd = [
            sys.executable, "-m", "cpppo.server.enip.client",
            "-a", "127.0.0.1",
            # Syntax: Tag=(Type)Value
            "Motor_Speed=(REAL)1500.0",
            "Tank_Level=(INT)75",
            "Internal_Debug=(STRING)DECOY_TAG",
            "Zone_4_Safety=(BOOL)1",
            "Secret_Project_Alpha=(SSTRING)FLAG{ENIP_TAG_LOOTER}"
        ]
        subprocess.run(init_cmd, check=True)
        print("[+] Flag and Data loaded successfully!")
        
    except subprocess.CalledProcessError:
        print("[-] Failed to initialize tags. Server might be unreachable.")
    
    # 4. Keep the script running so Docker doesn't exit
    print("[*] Server is running. Press Ctrl+C to stop.")
    server.wait()