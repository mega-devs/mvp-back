import json
import logging
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.exceptions import StopConsumer
from channels.db import database_sync_to_async
from asgiref.sync import sync_to_async
from django.core.cache import cache
import asyncio

logger = logging.getLogger('mailer')

class BaseWebSocketConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        if self.scope["user"].is_anonymous:
            await self.close()
            return

        self.user = self.scope["user"]
        self.session = self.scope["url_route"]["kwargs"]["session"]
        self.room_group_name = f"session_{self.session}"
        
        # Добавляем пользователя в группу
        await self.channel_layer.group_add(
            self.room_group_name,
            self.channel_name
        )
        
        # Сохраняем информацию о подключении
        await self.save_connection_info()
        
        await self.accept()
        
        # Отправляем статус подключения
        await self.send_json({
            'type': 'connection_established',
            'session': self.session
        })

    async def disconnect(self, close_code):
        try:
            # Удаляем информацию о подключении
            await self.remove_connection_info()
            
            # Удаляем пользователя из группы
            await self.channel_layer.group_discard(
                self.room_group_name,
                self.channel_name
            )
        except Exception as e:
            logger.error(f"Error in disconnect: {str(e)}")

    async def receive(self, text_data):
        try:
            data = json.loads(text_data)
            message_type = data.get('type')
            
            # Обработка различных типов сообщений
            handlers = {
                'ping': self.handle_ping,
                'status_request': self.handle_status_request,
                'reconnect': self.handle_reconnect
            }
            
            handler = handlers.get(message_type)
            if handler:
                await handler(data)
            else:
                await self.send_json({
                    'type': 'error',
                    'message': f'Unknown message type: {message_type}'
                })
                
        except json.JSONDecodeError:
            await self.send_json({
                'type': 'error',
                'message': 'Invalid JSON'
            })
        except Exception as e:
            logger.error(f"Error in receive: {str(e)}")
            await self.send_json({
                'type': 'error',
                'message': str(e)
            })

    async def send_json(self, content):
        """Отправка JSON сообщения"""
        try:
            await self.send(text_data=json.dumps(content))
        except Exception as e:
            logger.error(f"Error sending message: {str(e)}")

    @database_sync_to_async
    def save_connection_info(self):
        """Сохранение информации о подключении"""
        key = f"ws_connection:{self.channel_name}"
        info = {
            'user_id': self.user.id,
            'session': self.session,
            'channel_name': self.channel_name
        }
        cache.set(key, info, timeout=3600)

    @database_sync_to_async
    def remove_connection_info(self):
        """Удаление информации о подключении"""
        key = f"ws_connection:{self.channel_name}"
        cache.delete(key)

    async def handle_ping(self, data):
        """Обработка ping сообщений"""
        await self.send_json({
            'type': 'pong',
            'timestamp': data.get('timestamp')
        })

    async def handle_status_request(self, data):
        """Обработка запроса статуса"""
        status = await self.get_session_status()
        await self.send_json({
            'type': 'status_response',
            'status': status
        })

    async def handle_reconnect(self, data):
        """Обработка переподключения"""
        try:
            old_channel = data.get('channel_name')
            if old_channel:
                await self.channel_layer.group_discard(
                    self.room_group_name,
                    old_channel
                )
            await self.send_json({
                'type': 'reconnect_success',
                'channel_name': self.channel_name
            })
        except Exception as e:
            logger.error(f"Reconnection failed: {str(e)}")
            await self.send_json({
                'type': 'reconnect_failed',
                'error': str(e)
            })

    @database_sync_to_async
    def get_session_status(self):
        """Получение статуса сессии"""
        # Здесь можно добавить логику получения статуса
        return {
            'active': True,
            'connected_users': self.get_connected_users(),
            'last_activity': self.get_last_activity()
        }

    def get_connected_users(self):
        """Получение списка подключенных пользователей"""
        pattern = "ws_connection:*"
        connections = cache.keys(pattern)
        users = set()
        for conn in connections:
            info = cache.get(conn)
            if info and info['session'] == self.session:
                users.add(info['user_id'])
        return len(users)

    def get_last_activity(self):
        """Получение времени последней активности"""
        key = f"session_activity:{self.session}"
        return cache.get(key)
