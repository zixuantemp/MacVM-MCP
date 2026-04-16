FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends openssh-client \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY pyproject.toml requirements.txt ./
COPY server.py mac_connection.py ./
COPY resources ./resources
COPY prompts ./prompts
COPY skills ./skills
RUN pip install --no-cache-dir -e .
ENTRYPOINT ["python", "server.py"]
