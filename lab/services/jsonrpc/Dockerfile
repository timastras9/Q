FROM python:3.9-slim
WORKDIR /app
RUN pip install flask
COPY server.py .
EXPOSE 8087
CMD ["python3", "server.py"]
