FROM python:3.13-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY triage/ triage/
COPY web/ web/
COPY problem_c_data/ problem_c_data/
EXPOSE 8000
CMD ["sh", "-c", "uvicorn triage.api:app --host 0.0.0.0 --port ${PORT:-8000}"]
