FROM python:3.11-slim

WORKDIR /app

# Установка системных зависимостей
RUN apt-get update && apt-get install -y \
    gcc \
    default-libmysqlclient-dev \
    pkg-config \
    libmagic1 \
    && rm -rf /var/lib/apt/lists/*

# Копирование requirements.txt
COPY requirements.txt .

# Обновление pip и установка зависимостей
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Создание структуры директорий
RUN mkdir -p /app/mailer/middleware

# Копирование проекта
COPY . .

# Сбор статических файлов
RUN python manage.py collectstatic --noinput

# Проверка структуры файлов
RUN echo "Listing files in /app/mailer:" && \
    ls -la /app/mailer/ && \
    echo "Content of middleware/auth.py:" && \
    cat /app/mailer/middleware/auth.py

# Установка прав на middleware
RUN chmod -R 755 /app/mailer/middleware \
    && chown -R root:root /app/mailer/middleware \
    && ls -la /app/mailer/middleware/

# Создание необходимых директорий
RUN mkdir -p /app/staticfiles /app/media /var/log/celery
RUN mkdir -p /app/logs && chmod 777 /app/logs

# Установка прав на Python-пакеты
RUN find /app -type d -exec chmod 755 {} \; \
    && find /app -type f -exec chmod 644 {} \;

EXPOSE 8000

# Команда по умолчанию
CMD ["daphne", "-b", "0.0.0.0", "-p", "8000", "config.asgi:application"] 