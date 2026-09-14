# Tails the DC's JSON audit logs and forwards them to LibraX.
FROM python:3.12-slim

RUN pip install --no-cache-dir requests==2.32.3

COPY ship.py /app/ship.py
WORKDIR /app

ENTRYPOINT ["python", "-u", "ship.py"]
