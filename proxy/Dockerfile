FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY sentinel.py .

RUN mkdir -p /var/log/sentinel

EXPOSE 8080

CMD ["python", "sentinel.py"]
