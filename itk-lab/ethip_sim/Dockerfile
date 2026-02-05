FROM python:3.9-slim

# Install the library
RUN pip install cpppo

# Expose the EtherNet/IP port
EXPOSE 44818

# Copy the new python launcher script
COPY ethip_server.py .

# Run the launcher
CMD ["python", "ethip_server.py"]