FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 DATABASE=/app/data/portal.db
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && useradd --uid 10001 --create-home portal
COPY --chown=portal:portal . .
RUN mkdir -p /app/data && chown portal:portal /app/data
USER portal
EXPOSE 8000
CMD ["waitress-serve", "--listen=0.0.0.0:8000", "--threads=4", "--call", "app:create_app"]
