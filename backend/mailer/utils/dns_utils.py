import dns.resolver
import dns.reversename
import logging
from typing import List, Tuple, Optional
from email_validator import validate_email, EmailNotValidError
from django.conf import settings

logger = logging.getLogger('mailer')

class DNSUtils:
    @staticmethod
    def check_mx_record(domain: str) -> Tuple[bool, Optional[List[str]]]:
        """Проверка MX записей домена"""
        try:
            mx_records = dns.resolver.resolve(domain, 'MX')
            return True, [str(mx.exchange) for mx in mx_records]
        except Exception as e:
            logger.error(f"MX check failed for {domain}: {str(e)}")
            return False, None

    @staticmethod
    def check_spf_record(domain: str) -> Tuple[bool, Optional[str]]:
        """Проверка SPF записи"""
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
        """Проверка DKIM записи"""
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

    @staticmethod
    def check_dnsbl(ip: str) -> List[str]:
        """Проверка IP в DNSBL списках"""
        blacklisted = []
        reverse_ip = '.'.join(reversed(ip.split('.')))
        
        for dnsbl in settings.DNS_SETTINGS['dnsbls']:
            if dnsbl in settings.DNS_SETTINGS.get('skiplist', []):
                continue
                
            query = f"{reverse_ip}.{dnsbl}"
            try:
                dns.resolver.resolve(query, 'A')
                blacklisted.append(dnsbl)
            except dns.resolver.NXDOMAIN:
                continue
            except Exception as e:
                logger.error(f"DNSBL check failed for {ip} on {dnsbl}: {str(e)}")
                
        return blacklisted

class EmailUtils:
    @staticmethod
    def validate_email_address(email: str) -> Tuple[bool, Optional[str]]:
        """Валидация email адреса"""
        try:
            valid = validate_email(email)
            return True, valid.normalized
        except EmailNotValidError as e:
            return False, str(e)

    @staticmethod
    def validate_email_domain(email: str) -> Tuple[bool, dict]:
        """Комплексная проверка домена email"""
        try:
            # Базовая валидация
            valid, message = EmailUtils.validate_email_address(email)
            if not valid:
                return False, {'error': message}

            domain = email.split('@')[1]
            results = {
                'domain': domain,
                'valid': True,
                'mx': None,
                'spf': None,
                'dkim': None,
                'blacklisted': False
            }

            # Проверка MX
            mx_valid, mx_records = DNSUtils.check_mx_record(domain)
            results['mx'] = mx_records if mx_valid else None

            # Проверка SPF
            spf_valid, spf_record = DNSUtils.check_spf_record(domain)
            results['spf'] = spf_record if spf_valid else None

            # Проверка DKIM
            dkim_valid, dkim_record = DNSUtils.check_dkim_record('default', domain)
            results['dkim'] = dkim_record if dkim_valid else None

            # Проверка IP серверов в DNSBL
            if mx_records:
                for mx in mx_records:
                    try:
                        ip = str(dns.resolver.resolve(mx, 'A')[0])
                        blacklists = DNSUtils.check_dnsbl(ip)
                        if blacklists:
                            results['blacklisted'] = True
                            results['blacklists'] = blacklists
                            break
                    except Exception as e:
                        logger.error(f"IP resolution failed for {mx}: {str(e)}")

            return True, results

        except Exception as e:
            logger.error(f"Domain validation failed for {email}: {str(e)}")
            return False, {'error': str(e)} 