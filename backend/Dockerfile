FROM python:3.10

# Установка системных зависимостей
RUN apt-get update && apt-get install -y \
    default-libmysqlclient-dev \
    pkg-config \
    gcc \
    python3-dev \
    netcat-traditional \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Сначала копируем requirements и устанавливаем зависимости
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Создаем директории для статики и медиа
RUN mkdir -p staticfiles media static

# Копируем весь проект
COPY . .

# Добавляем скрипт для запуска
COPY ./entrypoint.sh /
RUN chmod +x /entrypoint.sh

# Теперь можно собрать статику, так как все файлы проекта уже скопированы
RUN python manage.py collectstatic --noinput

CMD ["/entrypoint.sh"] 