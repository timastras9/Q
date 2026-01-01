FROM python:3.9-slim

WORKDIR /app

RUN pip install flask pyjwt

COPY app.py .

EXPOSE 5002

CMD ["python", "app.py"]
