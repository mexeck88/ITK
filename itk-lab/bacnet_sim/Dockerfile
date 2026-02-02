FROM python:3.9-slim

RUN apt-get update && apt-get install -y \
    net-tools \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

RUN pip install BAC0 pytz netifaces

COPY bacnet_server.py .
# Standard BACnet port is 47808
CMD ["python", "bacnet_server.py"]