FROM python:3.9-slim

RUN pip install impacket

WORKDIR /app
COPY rpc_server.py .

EXPOSE 135 593

CMD ["python3", "rpc_server.py"]
