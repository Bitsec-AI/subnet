FROM python:3.11-slim

RUN apt-get update \
    && apt-get install -y \
      build-essential pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt /app/

RUN pip install --no-cache-dir -r requirements.txt

CMD ["/bin/bash"]
