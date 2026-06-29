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

# Create a non-root user and switch to it
RUN useradd --create-home --shell /bin/bash appuser
USER appuser

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:5000/health || exit 1

CMD ["python3", "app.py"]
