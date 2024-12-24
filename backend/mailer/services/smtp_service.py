import smtplib
import socks
import socket
import logging
import re
from typing import Optional, Tuple, Dict
from django.conf import settings
from ..metrics import smtp_check_total, smtp_check_duration, timer
from django.core.cache import cache
from ..utils.cache_utils import cache_result
from ..utils.dns_utils import EmailUtils, DNSUtils
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import ssl
import time

logger = logging.getLogger('mailer')

class SMTPService:
    def __init__(self, smtp_settings=None):
        self.settings = smtp_settings or settings.SMTP_SETTINGS
        self.timeout = self.settings.get('timeout', 60)
        self.max_attempts = self.settings.get('max_attempts', 3)

    @cache_result('smtp_validate', timeout=60*60)
    def validate_smtp_config(self, config: Dict) -> Tuple[bool, str]:
        """Валидация SMTP конфигурации"""
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

        # Проверка email
        valid, message = EmailUtils.validate_email_address(config['email'])
        if not valid:
            return False, f"Invalid email: {message}"

        # Проверка домена
        valid, results = EmailUtils.validate_email_domain(config['email'])
        if not valid:
            return False, f"Domain validation failed: {results['error']}"

        if results.get('blacklisted'):
            return False, f"Domain is blacklisted in: {', '.join(results['blacklists'])}"

        return True, "Valid configuration"

    @cache_result('smtp_check', timeout=60*15)
    def check_smtp(
        self, 
        server: str, 
        port: int, 
        email: str, 
        password: str, 
        proxy: Optional[Dict] = None,
        timeout: int = None
    ) -> Tuple[bool, str]:
        """Проверка SMTP сервера"""
        try:
            # Валидация конфигурации
            valid, message = SMTPService.validate_smtp_config({
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

            # Подключение к SMTP
            try:
                with timer(smtp_check_duration):
                    context = ssl.create_default_context()
                    
                    with smtplib.SMTP(server, port, timeout=timeout or self.timeout) as server:
                        server.starttls(context=context)
                        server.login(email, password)
                        
                smtp_check_total.labels(status='success').inc()
                return True, "Success"
                
            except smtplib.SMTPAuthenticationError:
                return False, "Authentication failed"
            except smtplib.SMTPConnectError:
                return False, "Connection failed"
            except smtplib.SMTPServerDisconnected:
                return False, "Server disconnected"
            except smtplib.SMTPException as e:
                return False, f"SMTP error: {str(e)}"
            
        except Exception as e:
            smtp_check_total.labels(status='failure').inc()
            logger.error(f"SMTP check failed: {str(e)}")
            return False, str(e)
        finally:
            if proxy:
                socks.setdefaultproxy()
                socket.socket = socks.socksocket

    def send_email(self, smtp, to_email, subject, body, proxy=None):
        """Отправка email"""
        try:
            msg = MIMEMultipart()
            msg['From'] = smtp.email
            msg['To'] = to_email
            msg['Subject'] = subject
            
            msg.attach(MIMEText(body, 'html'))
            
            context = ssl.create_default_context()
            
            with smtplib.SMTP(smtp.server, int(smtp.port), timeout=self.timeout) as server:
                server.starttls(context=context)
                server.login(smtp.email, smtp.password)
                server.send_message(msg)
                
            return True
            
        except Exception as e:
            logger.error(f"Failed to send email: {str(e)}")
            return False

class DNSUtils:
    @staticmethod
    def check_mx_record(domain: str) -> Tuple[bool, Optional[list[str]]]:
        """
        Check the MX records for the given domain.

        Args:
            domain (str): The domain to check.

        Returns:
            Tuple[bool, Optional[List[str]]]: A tuple where the first value indicates success,
            and the second value contains a list of MX records or None on failure.
        """
        try:
            mx_records = dns.resolver.resolve(domain, 'MX')
            return True, [str(mx.exchange) for mx in mx_records]
        except Exception as e:
            logger.error(f"MX check failed for {domain}: {str(e)}")
            return False, None

    @staticmethod
    def check_spf_record(domain: str) -> Tuple[bool, Optional[str]]:
        """
        Check the SPF record for the given domain.

        Args:
            domain (str): The domain to check.

        Returns:
            Tuple[bool, Optional[str]]: A tuple where the first value indicates success,
            and the second contains the SPF record string or None on failure.
        """
        try:
            txt_records = dns.resolver.resolve(domain, 'TXT')
            for record in txt_records:
                for string in record.strings:
                    if string.startswith(b'v=spf1'):
                        return True, string.decode()
            return False, None
        except Exception as e:
            logger.error(f"SPF check failed for {domain}: {str(e)}")
            return False, None

    @staticmethod
    def check_dkim_record(selector: str, domain: str) -> Tuple[bool, Optional[str]]:
        """
        Check the DKIM record for the given domain using the specified selector.

        Args:
            selector (str): The DKIM selector (e.g., 'default').
            domain (str): The domain to check.

        Returns:
            Tuple[bool, Optional[str]]: A tuple where the first value indicates success,
            and the second contains the DKIM record string or None on failure.
        """
        try:
            dkim_domain = f"{selector}._domainkey.{domain}"
            txt_records = dns.resolver.resolve(dkim_domain, 'TXT')
            for record in txt_records:
                for string in record.strings:
                    if string.startswith(b'v=DKIM1'):
                        return True, string.decode()
            return False, None
        except Exception as e:
            logger.error(f"DKIM check failed for {domain}: {str(e)}")
            return False, None
