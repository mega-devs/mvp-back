import requests
import socks
import socket
import logging
import re
from typing import Optional, Tuple, Dict, List
from django.conf import settings
from ..metrics import proxy_check_total, proxy_check_duration, timer
from django.core.cache import cache
from ..utils.cache_utils import cache_result

logger = logging.getLogger('mailer')

class ProxyService:
    def __init__(self, proxy_settings=None):
        self.settings = proxy_settings or settings.PROXY_SETTINGS
        self.timeout = settings.SMTP_SETTINGS.get('timeout', 60)
        self.ip_apis = self.settings.get('ip_apis', [])
        self.recheck_ip = self.settings.get('recheck_ip', True)

    @cache_result('proxy_validate', timeout=60*60)
    def validate_proxy_config(self, proxy: Dict) -> Tuple[bool, str]:
        """Валидация конфигурации прокси"""
        required_fields = ['ip', 'port']
        for field in required_fields:
            if field not in proxy:
                return False, f"Missing required field: {field}"

        # Валидация IP
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if not re.match(ip_pattern, proxy['ip']):
            return False, "Invalid IP format"

        # Проверка октетов IP
        octets = proxy['ip'].split('.')
        if not all(0 <= int(octet) <= 255 for octet in octets):
            return False, "Invalid IP address values"

        # Валидация порта
        try:
            port = int(proxy['port'])
            if port < 1 or port > 65535:
                return False, "Invalid port number"
        except ValueError:
            return False, "Port must be a number"

        return True, "Valid configuration"

    @cache_result('proxy_check', timeout=60*15)
    def check_proxy(self, proxy_config: Dict) -> Tuple[bool, str]:
        """Проверка прокси"""
        try:
            with timer(proxy_check_duration):
                # Настройка прокси
                proxy_url = f"socks5://{proxy_config['ip']}:{proxy_config['port']}"
                proxies = {
                    'http': proxy_url,
                    'https': proxy_url
                }

                # Проверка через несколько IP API
                for api_url in self.ip_apis:
                    try:
                        response = requests.get(
                            api_url,
                            proxies=proxies,
                            timeout=self.timeout
                        )
                        if response.status_code == 200:
                            proxy_check_total.labels(status='success').inc()
                            return True, "Success"
                    except requests.RequestException:
                        continue

                proxy_check_total.labels(status='failure').inc()
                return False, "Failed to connect through proxy"

        except Exception as e:
            proxy_check_total.labels(status='failure').inc()
            logger.error(f"Proxy check failed: {str(e)}")
            return False, str(e)

    def get_proxy_info(self, proxy_config: Dict) -> Dict:
        """Получение информации о прокси"""
        try:
            proxy_url = f"socks5://{proxy_config['ip']}:{proxy_config['port']}"
            proxies = {
                'http': proxy_url,
                'https': proxy_url
            }

            info = {
                'ip': proxy_config['ip'],
                'port': proxy_config['port'],
                'type': 'socks5',
                'working': False,
                'country': None,
                'anonymity': None,
                'response_time': None
            }

            # Проверка работоспособности
            for api_url in self.ip_apis:
                try:
                    start_time = time.time()
                    response = requests.get(
                        api_url,
                        proxies=proxies,
                        timeout=self.timeout
                    )
                    info['response_time'] = time.time() - start_time

                    if response.status_code == 200:
                        info['working'] = True
                        data = response.json()
                        info['country'] = data.get('country')
                        break
                except:
                    continue

            return info

        except Exception as e:
            logger.error(f"Failed to get proxy info: {str(e)}")
            return None

    @staticmethod
    def get_working_proxy(proxies: List[Dict], timeout: int = 10) -> Optional[Dict]:
        """Получение рабочего прокси из списка"""
        if settings.PROXY_SETTINGS['reverse_socks']:
            proxies = reversed(proxies)

        for proxy in proxies:
            success, _ = ProxyService.check_proxy(proxy, timeout)
            if success:
                return proxy

        return None

    def setup_proxy(self, proxy):
        # существующий код
        pass