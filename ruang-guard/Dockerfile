FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && useradd --uid 10001 --create-home guard && mkdir /data && chown guard:guard /data
COPY guard ./guard
USER guard
CMD ["waitress-serve", "--listen=0.0.0.0:8080", "--threads=8", "--connection-limit=100", "--max-request-body-size=16384", "--max-request-header-size=16384", "--channel-timeout=15", "--call", "guard.gateway:create_app"]
