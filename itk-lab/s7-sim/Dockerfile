FROM python:3.9-slim
RUN apt-get update && apt-get install -y libsnap7-dev build-essential
RUN pip install python-snap7
COPY s7_server.py .
CMD ["python", "s7_server.py"]