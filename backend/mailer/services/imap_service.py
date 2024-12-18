import imaplib
import socks
import socket
import logging
import re
from typing import Optional, Tuple, Dict, List
from django.conf import settings

logger = logging.getLogger('mailer')

class IMAPService:
    @staticmethod
    def validate_imap_config(config: Dict) -> Tuple[bool, str]:
        """Валидация IMAP конфигурации"""
        required_fields = ['server', 'port', 'email', 'password']
        for field in required_fields:
            if field not in config:
                return False, f"Missing required field: {field}"

        # Валидация порта
        try:
            port = int(config['port'])
            if port < 1 or port > 65535:
                return False, "Invalid port number"
        except ValueError:
            return False, "Port must be a number"

        # Валидация email
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, config['email']):
            return False, "Invalid email format"

        # Валидация сервера
        server_pattern = r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(server_pattern, config['server']):
            return False, "Invalid server format"

        return True, "Valid configuration"

    @staticmethod
    def check_imap(
        server: str,
        port: int,
        email: str,
        password: str,
        proxy: Optional[Dict] = None,
        timeout: int = 30
    ) -> Tuple[bool, str]:
        """Проверка IMAP сервера"""
        original_socket = socket.socket
        try:
            # Валидация конфигурации
            valid, message = IMAPService.validate_imap_config({
                'server': server,
                'port': port,
                'email': email,
                'password': password
            })
            if not valid:
                return False, message

            # Настройка прокси
            if proxy:
                try:
                    socks.setdefaultproxy(
                        socks.PROXY_TYPE_SOCKS5,
                        proxy['ip'],
                        int(proxy['port'])
                    )
                    socket.socket = socks.socksocket
                except Exception as e:
                    return False, f"Proxy configuration error: {str(e)}"

            # Подключение к IMAP
            try:
                imap = imaplib.IMAP4_SSL(server, port, timeout=timeout)
                imap.login(email, password)

                # Проверяем доступ к папкам
                status, folders = imap.list()
                if status != 'OK':
                    return False, "Failed to list folders"

                # Проверяем INBOX
                status, messages = imap.select('INBOX')
                if status != 'OK':
                    return False, "Failed to access INBOX"

                imap.logout()
                return True, "Success"

            except imaplib.IMAP4.error as e:
                return False, f"IMAP error: {str(e)}"
            except socket.timeout:
                return False, "Connection timeout"
            except socket.gaierror:
                return False, "Failed to resolve server address"
            except ConnectionRefusedError:
                return False, "Connection refused"

        except Exception as e:
            logger.error(f"IMAP check failed: {str(e)}")
            return False, str(e)
        finally:
            if proxy:
                socket.socket = original_socket

    @staticmethod
    def get_mailbox_stats(
        server: str,
        port: int,
        email: str,
        password: str,
        proxy: Optional[Dict] = None,
        timeout: int = 30
    ) -> Dict:
        """Получение статистики почтового ящика"""
        try:
            success, message = IMAPService.check_imap(
                server, port, email, password, proxy, timeout
            )
            if not success:
                return {'error': message}

            imap = imaplib.IMAP4_SSL(server, port, timeout=timeout)
            imap.login(email, password)

            stats = {
                'total_messages': 0,
                'folders': [],
                'quota': None
            }

            # Получаем список папок
            status, folders = imap.list()
            if status == 'OK':
                for folder in folders:
                    folder_name = folder.decode().split('"/"')[-1].strip('" ')
                    status, messages = imap.select(folder_name)
                    if status == 'OK':
                        stats['folders'].append({
                            'name': folder_name,
                            'messages': int(messages[0])
                        })
                        stats['total_messages'] += int(messages[0])

            # Пробуем получить квоту
            try:
                status, quota = imap.getquotaroot('INBOX')
                if status == 'OK' and len(quota) > 1:
                    stats['quota'] = {
                        'used': int(quota[1].split()[2]),
                        'total': int(quota[1].split()[3])
                    }
            except:
                pass

            imap.logout()
            return stats

        except Exception as e:
            logger.error(f"Failed to get mailbox stats: {str(e)}")
            return {'error': str(e)}