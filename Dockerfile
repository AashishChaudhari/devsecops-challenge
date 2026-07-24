# ---- Stage 1: builder ----
FROM python:3.12-slim AS builder

WORKDIR /app

COPY requirements.txt .
# Install dependencies into a separate location we can copy later
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# ---- Stage 2: final, minimal image ----
FROM python:3.12-slim

WORKDIR /app

# Copy only the installed packages from the builder stage — no pip cache, no build tools
COPY --from=builder /install /usr/local

COPY app.py .
COPY database.py .
COPY logger.py .
COPY gunicorn.conf.py .
COPY config.py .
COPY notifications.py .
COPY middleware.py .
COPY password_validator.py .

RUN useradd --create-home --shell /bin/bash appuser
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /app/data && chown -R appuser:appuser /app

USER appuser

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:5000/health || exit 1

CMD ["gunicorn", "-c", "gunicorn.conf.py", "app:app"]
