FROM python:3.11

WORKDIR /app

COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt
RUN apt update
RUN apt install nano -y

COPY . /app/

ENV PYTHONUNBUFFERED=1 \
    DJANGO_SETTINGS_MODULE=http_anomaly_detector.settings

CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "4", "http_anomaly_detector.wsgi:application"]
