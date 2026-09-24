# Use an official lightweight Python image
FROM python:3.11-slim

# Install system dependencies (git for cloning, openssl/bash for cert.sh if needed)
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    bash \
    openssl \
    && rm -rf /var/lib/apt/lists/*

# Set the working directory inside the container
WORKDIR /app

# Upgrade pip
RUN pip install --upgrade pip

# 1. Clone and install the backend peer dependencies (keymaker-proto and keymaker-ui)
# We place it outside the main /app folder to mimic your peer folder setup
WORKDIR /workspace
RUN git clone https://github.com/apadartha-code/keymaker-proto.git \
    && cd keymaker-proto \
    && pip install -e . \
    && cd .. \
    && git clone https://github.com/apadartha-code/keymaker-ui.git \
    && cd keymaker-ui \
    && pip install -e .

# 2. Copy the current project (vault-proto) into /app
WORKDIR /app
COPY . /app

# Make the cert script executable and run it to generate self-signed certs
# Also, create a FIFO to communicate the startup nonce when running detached
# inside a container. Remember to add a data directory for persistence.
RUN pip install -r ./requirements.txt \
    && chmod +x cert.sh \
    && ./cert.sh \
    && mkfifo /tmp/vault_fifo \
    && mkdir data

# Expose the Flask port
EXPOSE 5000

# Run the application
# Configure the container to run python app.py by default
ENTRYPOINT ["python", "app.py"]

# Default arguments passed to app.py if the user doesn't provide any
CMD []