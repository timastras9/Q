FROM python:3.9-slim

RUN pip install flask

WORKDIR /app
COPY app.py .

EXPOSE 8443

CMD ["python3", "app.py"]
