#!/bin/bash

# Максимальное время ожидания БД
MAX_TRIES=30
WAIT_SECONDS=2

# Ждем готовности базы данных
echo "Waiting for database..."
for i in $(seq 1 $MAX_TRIES); do
    if nc -z db 3306; then
        echo "Database is up!"
        break
    fi
    
    if [ $i -eq $MAX_TRIES ]; then
        echo "Database connection timeout"
        exit 1
    fi
    
    echo "Waiting for database... $i/$MAX_TRIES"
    sleep $WAIT_SECONDS
done

# Применяем миграции
echo "Applying migrations..."
python manage.py migrate --noinput

# Собираем статические файлы
echo "Collecting static files..."
python manage.py collectstatic --noinput

# Запускаем сервер
echo "Starting server..."
exec daphne -b 0.0.0.0 -p 8000 config.asgi:application