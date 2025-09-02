#!/bin/bash

echo "Starting Celery worker in background..."
celery -A celery_app worker --loglevel=info --autoscale=50,1 --detach

echo "Starting Celery beat in background..."
celery -A celery_app beat --loglevel=info --detach

echo "Starting aiohttp server..."
python main.py
