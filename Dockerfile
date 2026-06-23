FROM python:3.12-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends curl git unzip && rm -rf /var/lib/apt/lists/*
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY backend/app ./app
COPY backend/yara_rules ./yara_rules
COPY backend/entrypoint.sh ./entrypoint.sh
COPY collectors ./collectors
RUN chmod +x ./entrypoint.sh
EXPOSE 8080
CMD ["./entrypoint.sh"]
