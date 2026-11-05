FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && useradd --uid 10001 --create-home catalog
COPY app.py .
COPY templates ./templates
COPY static ./static
USER catalog
CMD ["waitress-serve", "--listen=0.0.0.0:8000", "--threads=4", "--max-request-body-size=16384", "--call", "app:create_app"]
