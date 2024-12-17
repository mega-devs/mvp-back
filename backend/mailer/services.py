from dataclasses import dataclass
import smtplib
import imaplib
import socks
import socket
import random
import string
import threading
import queue
import requests
from time import sleep
from typing import Optional, Tuple, List
import logging
from django.utils import timezone
import concurrent.futures
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formataddr

from .models import *

logger = logging.getLogger('mailer')

@dataclass
class SMTPConfig:
    server: str
    port: int
    email: str
    password: str

    def line(self) -> str:
        return f"{self.server}:{self.port}:{self.email}:{self.password}"

@dataclass
class IMAPConfig:
    server: str
    port: int
    email: str
    password: str
    connect_timeout: int
    connect_attempts: int

    def line(self) -> str:
        return f"{self.server}:{self.port}:{self.email}:{self.password}"

class MailerService:
    @staticmethod
    def get_rand_string(n: int) -> str:
        return ''.join(random.choices(string.ascii_uppercase + string.digits, k=n))

    @staticmethod
    def connect_smtp(smtp: SMTPConfig, proxy: Optional[str] = None) -> Tuple[Optional[smtplib.SMTP], Optional[str]]:
        logger.info(f'Starting SMTP connection for {smtp.email} with proxy {proxy}')
        
        for attempt in range(3):
            if proxy:
                sleep(random.uniform(0.1, 10))
                host, port = proxy.split(':')
                socks.setdefaultproxy(socks.SOCKS5, host, int(port), True)
                socket.socket = socks.socksocket
                
            try:
                if smtp.port == 587:
                    server = smtplib.SMTP(smtp.server, smtp.port, timeout=45)
                    server.starttls()
                elif smtp.port == 465:
                    server = smtplib.SMTP_SSL(smtp.server, smtp.port, timeout=45)
                else:
                    server = smtplib.SMTP(smtp.server, timeout=45)
                    try:
                        server.starttls()
                    except:
                        pass
                        
                server.login(smtp.email, smtp.password)
                logger.info(f'Successfully connected to SMTP server {smtp.server}')
                return server, proxy
                
            except Exception as e:
                logger.error(f'SMTP connection error: {str(e)}')
                continue
                
        return None, None

    @staticmethod
    def check_proxy(proxy: str) -> bool:
        try:
            host, port = proxy.split(':')
            socks.setdefaultproxy(socks.SOCKS5, host, int(port), True)
            socket.socket = socks.socksocket
            
            with smtplib.SMTP('smtp.gmail.com', 587, timeout=10) as server:
                server.ehlo()
                return True
        except Exception as e:
            logger.error(f'Proxy check error: {str(e)}')
            return False
        finally:
            socks.setdefaultproxy()

    @staticmethod
    def connect_imap(imap: IMAPConfig, proxy: Optional[str] = None) -> Optional[imaplib.IMAP4_SSL]:
        logger.info(f'Starting IMAP connection for {imap.email} with proxy {proxy}')
        
        socket.setdefaulttimeout(imap.connect_timeout)
        for _ in range(imap.connect_attempts):
            try:
                if proxy:
                    host, port = proxy.split(':')
                    socks.setdefaultproxy(socks.SOCKS5, host, int(port), True)
                    socket.socket = socks.socksocket

                server = imaplib.IMAP4_SSL(imap.server, imap.port)
                server.login(imap.email, imap.password)
                logger.info(f'Successfully connected to IMAP server {imap.server}')
                return server
            except Exception as e:
                logger.error(f'IMAP connection error: {str(e)}')
                continue
        
        return None

    @staticmethod
    def prepare_email(data: dict) -> MIMEMultipart:
        """Prepare email message"""
        msg = MIMEMultipart('alternative')
        msg['Subject'] = data['subject']
        msg['From'] = formataddr(('', data['from']))
        msg['To'] = data['base']
        
        # Add HTML content
        html_part = MIMEText(data['template'], 'html')
        msg.attach(html_part)
        
        return msg

    @classmethod
    def send_email(cls, data: dict, delay: float = 0.3) -> bool:
        sleep(delay)
        
        smtp_connection, proxy = cls.connect_smtp(data['smtp'], data['proxy'])
        if not smtp_connection:
            logger.error(f'Failed to connect to SMTP for {data["smtp"].email}')
            return False

        try:
            email_message = cls.prepare_email(data)
            smtp_connection.send_message(email_message)
            smtp_connection.quit()
            logger.info(f'Successfully sent email from {data["smtp"].email}')
            return True
        except Exception as e:
            logger.error(f'Error sending email: {str(e)}')
            return False

    @classmethod
    def check_smtps(cls, session: str, smtp_ids: List[str], proxy_ids: List[str], 
                    timeout: int = 45) -> Tuple[List[str], List[str]]:
        """Check SMTP servers and return valid and invalid SMTP emails"""
        valid_emails = []
        invalid_emails = []
        threads = []
        result_queue = queue.Queue()

        smtp_list = SMTP.objects.filter(id__in=smtp_ids, session=session)
        proxy_list = Proxy.objects.filter(id__in=proxy_ids, session=session)

        if not proxy_list.exists():
            logger.warning('No proxies available for SMTP check')
            return [], []

        def check_smtp_worker(smtp_obj, proxy, queue_obj):
            smtp_config = SMTPConfig(
                server=smtp_obj.server,
                port=int(smtp_obj.port),
                email=smtp_obj.email,
                password=smtp_obj.password
            )
            proxy_str = f"{proxy.ip}:{proxy.port}"
            
            connection, _ = cls.connect_smtp(smtp_config, proxy_str)
            queue_obj.put((smtp_obj.email, connection is not None))

        for smtp in smtp_list:
            proxy = random.choice(proxy_list)
            thread = threading.Thread(
                target=check_smtp_worker,
                args=(smtp, proxy, result_queue)
            )
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()
            
        while not result_queue.empty():
            email, is_valid = result_queue.get()
            if is_valid:
                valid_emails.append(email)
            else:
                invalid_emails.append(email)

        return valid_emails, invalid_emails

    @classmethod
    def test_mode(cls, session: str, data: dict) -> bool:
        """
        Run test mode for email sending
        """
        try:
            sending_limit = int(data.get('sending_limit', 200))
            threads_number = int(data.get('threads_number', 5))
            timeout = float(data.get('timeout', 45))
            delay = float(data.get('delay', 0.3))
            emails_per_session = int(data.get('emails_per_session', 3))
            emails_to_validate = int(data.get('emails_to_validate', 3))
            
            # Get required materials
            templates = Template.objects.filter(
                session=session, 
                id=data['template_id']
            )
            proxies = Proxy.objects.filter(
                session=session,
                id__in=data['proxy_ids']
            )
            smtps = SMTP.objects.filter(
                session=session,
                id__in=data['smtp_ids']
            )
            domains = Domain.objects.filter(
                session=session,
                id__in=data['domain_ids']
            )

            if not all([templates, proxies, smtps, domains]):
                logger.error('Missing required materials for test mode')
                return False

            threads = []
            sent_count = 0
            
            for template in templates:
                for _ in range(emails_per_session):
                    smtp = random.choice(smtps)
                    proxy = random.choice(proxies)
                    domain = random.choice(domains)

                    smtp_config = SMTPConfig(
                        server=smtp.server,
                        port=int(smtp.port),
                        email=smtp.email,
                        password=smtp.password
                    )

                    email_data = {
                        'smtp': smtp_config,
                        'template': template.template,
                        'from': template.froms,
                        'subject': template.subject,
                        'base': data.get('test_email'),
                        'proxy': f"{proxy.ip}:{proxy.port}",
                        'template_name': template.id
                    }

                    thread = threading.Thread(
                        target=cls.send_email,
                        args=(email_data, delay)
                    )
                    threads.append(thread)
                    
                    if len(threads) >= threads_number:
                        for t in threads:
                            t.start()
                        for t in threads:
                            t.join()
                        threads = []
                        
                    sent_count += 1
                    if sent_count >= sending_limit:
                        logger.info('Reached sending limit')
                        return True

            return True

        except Exception as e:
            logger.error(f'Error in test mode: {str(e)}')
            return False

    @classmethod
    def start_mailing(cls, session: str, data: dict) -> bool:
        """
        Start mass mailing campaign
        """
        try:
            sending_limit = int(data.get('sending_limit', 200))
            threads_number = int(data.get('threads_number', 5))
            delay = float(data.get('delay', 0.3))
            
            templates = Template.objects.filter(session=session, status='active')
            proxies = Proxy.objects.filter(session=session, status='active')
            smtps = SMTP.objects.filter(session=session, status='active')
            bases = Base.objects.filter(session=session, status='active')
            domains = Domain.objects.filter(session=session, status='active')

            if not all([templates, proxies, smtps, bases, domains]):
                logger.error('Missing required materials for mailing')
                return False

            threads = []
            sent_count = 0

            for base in bases:
                template = random.choice(templates)
                smtp = random.choice(smtps)
                proxy = random.choice(proxies)
                domain = random.choice(domains)

                smtp_config = SMTPConfig(
                    server=smtp.server,
                    port=int(smtp.port),
                    email=smtp.email,
                    password=smtp.password
                )

                email_data = {
                    'smtp': smtp_config,
                    'template': template.template,
                    'from': template.froms,
                    'subject': template.subject,
                    'base': base.email,
                    'proxy': f"{proxy.ip}:{proxy.port}",
                    'template_name': template.id
                }

                thread = threading.Thread(
                    target=cls.send_email,
                    args=(email_data, delay)
                )
                threads.append(thread)
                
                if len(threads) >= threads_number:
                    for t in threads:
                        t.start()
                    for t in threads:
                        t.join()
                    threads = []
                    
                sent_count += 1
                if sent_count >= sending_limit:
                    logger.info('Reached sending limit')
                    return True

            return True

        except Exception as e:
            logger.error(f'Error in mailing: {str(e)}')
            return False

    @classmethod
    def check_proxies(cls, session: str, proxy_ids: List[str]) -> Tuple[List[str], List[str]]:
        """Check proxy servers and return valid and invalid proxy IDs"""
        valid_proxies = []
        invalid_proxies = []
        threads = []
        result_queue = queue.Queue()

        proxy_list = Proxy.objects.filter(id__in=proxy_ids, session=session)

        def check_proxy_worker(proxy_obj, queue_obj):
            proxy_str = f"{proxy_obj.ip}:{proxy_obj.port}"
            is_valid = cls.check_proxy(proxy_str)
            queue_obj.put((proxy_obj.id, is_valid))

        for proxy in proxy_list:
            thread = threading.Thread(
                target=check_proxy_worker,
                args=(proxy, result_queue)
            )
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()
            
        while not result_queue.empty():
            proxy_id, is_valid = result_queue.get()
            if is_valid:
                valid_proxies.append(proxy_id)
            else:
                invalid_proxies.append(proxy_id)

        return valid_proxies, invalid_proxies

    @classmethod
    def check_domains(cls, session: str, domain_ids: List[str]) -> dict:
        """Check domains availability and status"""
        results = {
            'valid': [],
            'invalid': [],
            'errors': []
        }

        domains = Domain.objects.filter(id__in=domain_ids, session=session)
        threads = []
        result_queue = queue.Queue()

        def check_domain_worker(domain_obj, queue_obj):
            try:
                response = requests.get(domain_obj.url, timeout=30)
                is_valid = 200 <= response.status_code < 400
                queue_obj.put(('success', domain_obj.id, is_valid))
            except Exception as e:
                queue_obj.put(('error', domain_obj.id, str(e)))

        for domain in domains:
            thread = threading.Thread(
                target=check_domain_worker,
                args=(domain, result_queue)
            )
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        while not result_queue.empty():
            status, domain_id, result = result_queue.get()
            if status == 'success':
                if result:
                    results['valid'].append(domain_id)
                    Domain.objects.filter(id=domain_id).update(status='valid')
                else:
                    results['invalid'].append(domain_id)
                    Domain.objects.filter(id=domain_id).update(status='invalid')
            else:
                results['errors'].append({
                    'domain_id': domain_id,
                    'error': result
                })
                Domain.objects.filter(id=domain_id).update(status='error')

        return results

    @classmethod
    def check_imaps(cls, session: str, imap_ids: List[str]) -> dict:
        """Check IMAP servers"""
        results = {
            'valid': [],
            'invalid': [],
            'errors': []
        }

        imap_list = IMAP.objects.filter(id__in=imap_ids, session=session)
        threads = []
        result_queue = queue.Queue()

        def check_imap_worker(imap_obj, queue_obj):
            try:
                imap_config = IMAPConfig(
                    server=imap_obj.server,
                    port=int(imap_obj.port),
                    email=imap_obj.email,
                    password=imap_obj.password,
                    connect_timeout=30,
                    connect_attempts=3
                )
                
                connection = cls.connect_imap(imap_config)
                if connection:
                    queue_obj.put(('success', imap_obj.id, True))
                    connection.logout()
                else:
                    queue_obj.put(('success', imap_obj.id, False))
            except Exception as e:
                queue_obj.put(('error', imap_obj.id, str(e)))

        for imap in imap_list:
            thread = threading.Thread(
                target=check_imap_worker,
                args=(imap, result_queue)
            )
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        while not result_queue.empty():
            status, imap_id, result = result_queue.get()
            if status == 'success':
                if result:
                    results['valid'].append(imap_id)
                    IMAP.objects.filter(id=imap_id).update(status='valid')
                else:
                    results['invalid'].append(imap_id)
                    IMAP.objects.filter(id=imap_id).update(status='invalid')
            else:
                results['errors'].append({
                    'imap_id': imap_id,
                    'error': result
                })
                IMAP.objects.filter(id=imap_id).update(status='error')

        return results

    @classmethod
    def send_batch(cls, session: str, batch_size: int, delay: float) -> List[dict]:
        """Send batch of emails"""
        results = []
        
        templates = Template.objects.filter(session=session, status='active')
        proxies = Proxy.objects.filter(session=session, status='active')
        smtps = SMTP.objects.filter(session=session, status='active')
        bases = Base.objects.filter(session=session, status='active')[:batch_size]
        
        if not all([templates, proxies, smtps, bases]):
            logger.error('Missing required materials for batch sending')
            return results

        for base in bases:
            template = random.choice(templates)
            smtp = random.choice(smtps)
            proxy = random.choice(proxies)

            smtp_config = SMTPConfig(
                server=smtp.server,
                port=int(smtp.port),
                email=smtp.email,
                password=smtp.password
            )

            email_data = {
                'smtp': smtp_config,
                'template': template.template,
                'from': template.froms,
                'subject': template.subject,
                'base': base.email,
                'proxy': f"{proxy.ip}:{proxy.port}",
                'template_name': template.id
            }

            success = cls.send_email(email_data, delay)
            results.append({
                'success': success,
                'email': base.email,
                'smtp': smtp.email,
                'proxy': f"{proxy.ip}:{proxy.port}"
            })

        return results

    @classmethod
    def process_materials(cls, session: str, material_type: str, content: str) -> dict:
        """Process and validate materials"""
        processor_map = {
            'smtps': cls.process_smtp_material,
            'proxies': cls.process_proxy_material,
            'bases': cls.process_base_material,
            'domains': cls.process_domain_material,
        }
        
        if material_type not in processor_map:
            raise ValueError(f'Invalid material type: {material_type}')
            
        return processor_map[material_type](content, session)

    @staticmethod
    def process_proxy_material(content: str, session: str) -> dict:
        """Process and validate proxy list"""
        valid_count = 0
        invalid_count = 0
        proxies = []
        
        lines = utils.remove_duplicate_lines(content)
        for line in lines:
            try:
                ip, port = line.strip().split(':')
                proxies.append(
                    Proxy(
                        ip=ip,
                        port=port,
                        session=session,
                        status='new'
                    )
                )
                valid_count += 1
            except:
                invalid_count += 1
                
        if proxies:
            Proxy.objects.bulk_create(proxies)
            
        return {
            'valid': valid_count,
            'invalid': invalid_count,
            'total': len(lines)
        }

    @staticmethod
    def process_base_material(content: str, session: str) -> dict:
        """Process and validate email base"""
        valid_count = 0
        invalid_count = 0
        bases = []
        
        lines = utils.remove_duplicate_lines(content)
        for line in lines:
            if utils.validate_email(line.strip()):
                bases.append(
                    Base(
                        email=line.strip(),
                        session=session,
                        status='new'
                    )
                )
                valid_count += 1
            else:
                invalid_count += 1
                
        if bases:
            Base.objects.bulk_create(bases)
            
        return {
            'valid': valid_count,
            'invalid': invalid_count,
            'total': len(lines)
        }

    @staticmethod
    def process_domain_material(content: str, session: str) -> dict:
        """Process and validate domain list"""
        valid_count = 0
        invalid_count = 0
        domains = []
        
        lines = utils.remove_duplicate_lines(content)
        for line in lines:
            url = line.strip()
            if url.startswith(('http://', 'https://')):
                domains.append(
                    Domain(
                        url=url,
                        session=session,
                        status='new'
                    )
                )
                valid_count += 1
            else:
                invalid_count += 1
                
        if domains:
            Domain.objects.bulk_create(domains)
            
        return {
            'valid': valid_count,
            'invalid': invalid_count,
            'total': len(lines)
        }

    @staticmethod
    def process_template(template: str, replacements: dict) -> str:
        """Process template with replacements"""
        result = template
        for key, value in replacements.items():
            result = result.replace(f'%%{key}%%', str(value))
        return result

    @classmethod
    def validate_template(cls, template: str, test_data: dict = None) -> Tuple[bool, str]:
        """Validate template format and required placeholders"""
        required_placeholders = ['BODYID', 'SMTPID', 'PROXYID']
        
        # Check required placeholders
        for placeholder in required_placeholders:
            if f'%%{placeholder}%%' not in template:
                return False, f'Missing required placeholder: {placeholder}'
                
        # Try to process template with test data
        if test_data:
            try:
                cls.process_template(template, test_data)
            except Exception as e:
                return False, f'Template processing error: {str(e)}'
                
        return True, 'Template is valid'

    @classmethod
    def prepare_template_data(cls, template_obj: Template, base_obj: Base) -> dict:
        """Prepare data for template processing"""
        return {
            'EMAIL': base_obj.email,
            'FIRST': base_obj.first or '',
            'LAST': base_obj.last or '',
            'RANDOM': cls.get_rand_string(8),
            'DATE': timezone.now().strftime('%Y-%m-%d'),
            'TIME': timezone.now().strftime('%H:%M:%S'),
        }

    @classmethod
    def start_mass_mailing(cls, session: str, data: dict) -> bool:
        """Start mass mailing campaign with advanced settings"""
        try:
            sending_limit = int(data.get('sending_limit', 200))
            threads_number = int(data.get('threads_number', 5))
            delay = float(data.get('delay', 0.3))
            emails_per_smtp = int(data.get('emails_per_smtp', 3))
            
            # Get materials
            templates = Template.objects.filter(session=session, status='active')
            proxies = Proxy.objects.filter(session=session, status='active')
            smtps = SMTP.objects.filter(session=session, status='active')
            bases = Base.objects.filter(session=session, status='active')
            
            if not all([templates, proxies, smtps, bases]):
                logger.error('Missing required materials for mass mailing')
                return False

            # Initialize counters
            sent_count = 0
            error_count = 0
            
            # Create thread pool
            with concurrent.futures.ThreadPoolExecutor(max_workers=threads_number) as executor:
                futures = []
                
                # Split work between threads
                batch_size = sending_limit // threads_number
                for _ in range(threads_number):
                    future = executor.submit(
                        cls.process_mailing_batch,
                        session=session,
                        batch_size=batch_size,
                        emails_per_smtp=emails_per_smtp,
                        delay=delay
                    )
                    futures.append(future)
                
                # Wait for all threads to complete
                for future in concurrent.futures.as_completed(futures):
                    try:
                        batch_results = future.result()
                        sent_count += sum(1 for r in batch_results if r['success'])
                        error_count += sum(1 for r in batch_results if not r['success'])
                    except Exception as e:
                        logger.error(f'Error in mailing batch: {str(e)}')
                        error_count += 1

            logger.info(f'Mass mailing completed. Sent: {sent_count}, Errors: {error_count}')
            return True
            
        except Exception as e:
            logger.error(f'Error in mass mailing: {str(e)}')
            return False

    @classmethod
    def process_mailing_batch(cls, session: str, batch_size: int, emails_per_smtp: int, delay: float) -> List[dict]:
        """Process batch of emails for mass mailing"""
        results = []
        
        try:
            # Get materials for this batch
            templates = list(Template.objects.filter(session=session, status='active'))
            proxies = list(Proxy.objects.filter(session=session, status='active'))
            smtps = list(SMTP.objects.filter(session=session, status='active'))
            bases = list(Base.objects.filter(session=session, status='active')[:batch_size])
            
            if not all([templates, proxies, smtps, bases]):
                logger.error('Missing materials for batch processing')
                return results

            # Process emails
            current_smtp = None
            smtp_email_count = 0
            
            for base in bases:
                # Select SMTP server
                if current_smtp is None or smtp_email_count >= emails_per_smtp:
                    current_smtp = random.choice(smtps)
                    smtp_email_count = 0
                
                template = random.choice(templates)
                proxy = random.choice(proxies)
                
                # Prepare email data
                smtp_config = SMTPConfig(
                    server=current_smtp.server,
                    port=int(current_smtp.port),
                    email=current_smtp.email,
                    password=current_smtp.password
                )
                
                email_data = {
                    'smtp': smtp_config,
                    'template': template.template,
                    'from': template.froms,
                    'subject': template.subject,
                    'base': base.email,
                    'proxy': f"{proxy.ip}:{proxy.port}",
                    'template_name': template.id
                }
                
                # Send email
                success = cls.send_email(email_data, delay)
                results.append({
                    'success': success,
                    'email': base.email,
                    'smtp': current_smtp.email,
                    'proxy': f"{proxy.ip}:{proxy.port}"
                })
                
                smtp_email_count += 1
                
            return results
            
        except Exception as e:
            logger.error(f'Error processing mailing batch: {str(e)}')
            return results
