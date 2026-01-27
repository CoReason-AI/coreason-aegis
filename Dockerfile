# Stage 1: Builder
FROM python:3.12-slim AS builder

# Install build dependencies
RUN pip install --no-cache-dir build==1.3.0

# Set the working directory
WORKDIR /app

# Copy the project files
COPY pyproject.toml .
COPY src/ ./src/
COPY README.md .
COPY LICENSE .

# Build the wheel
RUN python -m build --wheel --outdir /wheels


# Stage 2: Runtime
FROM python:3.12-slim AS runtime

# Create a non-root user
RUN useradd --create-home --shell /bin/bash appuser

# Copy the wheel from the builder stage
COPY --from=builder /wheels /wheels

# Install the application wheel and download the Spacy model as root
# This ensures global availability and immutable installation
RUN pip install --no-cache-dir /wheels/*.whl && \
    python -m spacy download en_core_web_lg && \
    rm -f /usr/local/lib/python3.12/site-packages/setuptools/_vendor/jaraco/context.py && \
    rm -rf /usr/local/lib/python3.12/site-packages/setuptools/_vendor/jaraco.context-*.dist-info

# Set the working directory
WORKDIR /home/appuser/app

# Ensure the non-root user owns the working directory
RUN chown appuser:appuser /home/appuser/app

# Switch to non-root user
USER appuser

# Add user's local bin to PATH
ENV PATH="/home/appuser/.local/bin:${PATH}"

# Launch the Uvicorn server
CMD ["uvicorn", "coreason_aegis.server:app", "--host", "0.0.0.0", "--port", "8000"]
