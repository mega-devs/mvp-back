#!/bin/bash

# Ждем, пока база данных будет готова
echo "Waiting for database..."
python << END
import socket
import time
import sys

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
while True:
    try:
        s.connect(('db', 3306))
        s.close()
        break
    except socket.error:
        print("Database is not ready. Waiting...")
        time.sleep(1)
END
echo "Database is ready!"

# Даем MySQL время на полную инициализацию
sleep 5

# Создаем базу данных если её нет
echo "Creating database if not exists..."
python << END
import MySQLdb
try:
    db = MySQLdb.connect(host='db', user='root', password='246808642aA@')
    c = db.cursor()
    c.execute('CREATE DATABASE IF NOT EXISTS mailer CHARACTER SET utf8mb4')
    db.close()
except Exception as e:
    print(f"Error creating database: {e}")
END

# Применяем миграции
echo "Running migrations..."
python manage.py migrate auth
python manage.py migrate sessions
python manage.py migrate admin
python manage.py migrate contenttypes
python manage.py migrate django_celery_results
python manage.py migrate mailer --noinput

# Проверяем таблицы в базе
echo "Checking database tables..."
python << END
import MySQLdb
db = MySQLdb.connect(host='db', user='root', password='246808642aA@', database='mailer')
cursor = db.cursor()
cursor.execute("SHOW TABLES")
tables = cursor.fetchall()
print("Database tables:")
for table in tables:
    print(f"- {table[0]}")
db.close()
END

# Проверяем данные SMTP
echo "Checking SMTP data..."
python manage.py shell << END
from mailer.models import SMTP
print(f"SMTP count: {SMTP.objects.count()}")
for smtp in SMTP.objects.all():
    print(f"- {smtp.server} ({smtp.email})")
END

# Создаем суперпользователя если его нет
echo "Creating superuser if not exists..."
python manage.py shell << END
from django.contrib.auth import get_user_model
User = get_user_model()
if not User.objects.filter(username='admin').exists():
    User.objects.create_superuser('admin', 'admin@example.com', 'admin')
END

# Собираем статические файлы
echo "Collecting static files..."
python manage.py collectstatic --noinput

# Запускаем сервер
echo "Starting server..."
exec daphne -b 0.0.0.0 -p 8000 config.asgi:application