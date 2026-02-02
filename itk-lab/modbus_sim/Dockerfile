FROM python:3.9-slim
RUN pip install modsim
# Runs a virtual Modbus TCP device at localhost:5020
CMD ["python", "-m", "modsim", "--port", "5020"]