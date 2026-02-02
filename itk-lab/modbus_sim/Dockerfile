FROM python:3.9-slim
RUN pip install pymodbus>=3.0.0
RUN pip install --upgrade pymodbus
COPY server.py .
CMD ["python", "server.py"]