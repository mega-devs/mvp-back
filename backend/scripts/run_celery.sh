#!/bin/bash

# Запуск Celery worker
celery -A config worker -l INFO &

# Запуск Celery beat
celery -A config beat -l INFO &

# Ожидание завершения
wait 