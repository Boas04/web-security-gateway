FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1
WORKDIR /app
COPY requirements.txt requirements-ml.txt ./
RUN pip install --no-cache-dir -r requirements-ml.txt && useradd --uid 10001 --create-home guard && mkdir /data && chown guard:guard /data
COPY guard ./guard
USER guard
CMD ["python", "-m", "guard.ml_worker"]
