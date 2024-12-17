#!/bin/bash

# Ждем, пока база данных будет готова
echo "Waiting for database..."
while ! nc -z db 3306; do
  sleep 1
done
echo "Database is ready!"

# Применяем миграции
python manage.py migrate

# Запускаем сервер
exec daphne -b 0.0.0.0 -p 8000 config.asgi:application