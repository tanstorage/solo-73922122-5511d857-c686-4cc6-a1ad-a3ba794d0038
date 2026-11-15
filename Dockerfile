FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    APP_BASE_DIR=/app

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
# certs/ 由 compose 挂载（本地信任库），data/ 为共享命名卷
RUN mkdir -p /app/certs /app/data

EXPOSE 8000
# 单进程多线程；两个 compose 实例各跑一个 uvicorn，共享同一 SQLite 文件
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
