FROM --platform=linux/arm64 python:3.11-slim-bookworm

ARG AGENT_NAME
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY ${AGENT_NAME}/handler.py .
EXPOSE 8080
CMD ["python", "handler.py"]
