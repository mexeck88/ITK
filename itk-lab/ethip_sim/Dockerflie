FROM python:3.9-slim

RUN pip install cpppo

# Simulate a ControlLogix PLC with a FLAG tag for CTF purposes
# Launch with multiple tags: System status, PID loops, and the Flag
CMD ["python", "-m", "cpppo.server.enip", "--print", \
    "Motor_Speed=REAL=1500.0", \
    "Tank_Level=INT=75", \
    "Internal_Debug=STR=DECOY_TAG", \
    "Zone_4_Safety=BOOL=1", \
    "Secret_Project_Alpha=STR=FLAG{ENIP_TAG_LOOTER}"]