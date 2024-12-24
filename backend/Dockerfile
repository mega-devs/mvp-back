FROM python:3.11-slim

WORKDIR /app

# Установка только необходимых системных зависимостей
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    default-libmysqlclient-dev \
    pkg-config \
    netcat-traditional \
    dos2unix \
    libmagic1 \
    && rm -rf /var/lib/apt/lists/*

# Копируем сначала requirements.txt для кэширования слоя с зависимостей
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Создаем пользователя для приложения
RUN useradd -m appuser && \
    chown -R appuser:appuser /app
    
# Copy entrypoint.sh before switching users
COPY entrypoint.sh /app/
RUN chmod +x /app/entrypoint.sh

# Копируем остальные файлы проекта
COPY --chown=appuser:appuser . .

# Переключаемся на пользователя приложения
USER appuser

EXPOSE 8000

ENTRYPOINT ["/bin/bash", "/app/entrypoint.sh"]