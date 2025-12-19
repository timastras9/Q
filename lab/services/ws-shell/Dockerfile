FROM python:3.9-slim

RUN pip install websockets

WORKDIR /app
COPY shell.py .

EXPOSE 8888

CMD ["python3", "shell.py"]
