import logging
from typing import Dict, List, Optional
from django.conf import settings
from rest_framework import serializers
from ..models import Base, SMTP, Proxy, Template
from .smtp_service import SMTPService
from .proxy_service import ProxyService
from ..metrics import mailing_total, mailing_duration, timer
from django.core.cache import cache
from ..utils.cache_utils import cache_result

logger = logging.getLogger('mailer')

class MailingRequestSerializer(serializers.Serializer):
    session = serializers.CharField()
    template_id = serializers.IntegerField()
    smtp_id = serializers.IntegerField()
    proxy_id = serializers.IntegerField(required=False)
    test_mode = serializers.BooleanField(default=False)
    test_email = serializers.EmailField(required=False)

class MailerService:
    def __init__(self):
        self.smtp_service = SMTPService()
        self.proxy_service = ProxyService()

    def send_mass_mail(self, request_data: Dict) -> Dict:
        """Массовая рассылка писем"""
        try:
            with timer(mailing_duration):
                # Валидация запроса
                serializer = MailingRequestSerializer(data=request_data)
                serializer.is_valid(raise_exception=True)
                data = serializer.validated_data

                # Получение необходимых объектов
                template = Template.objects.get(id=data['template_id'])
                smtp = SMTP.objects.get(id=data['smtp_id'])
                proxy = None
                if data.get('proxy_id'):
                    proxy = Proxy.objects.get(id=data['proxy_id'])

                # Получение базы для рассылки
                if data.get('test_mode'):
                    base = [{'email': data['test_email']}]
                else:
                    base = Base.objects.filter(
                        session=data['session'],
                        status='new'
                    ).values('email')

                # Отправка писем
                success_count = 0
                for recipient in base:
                    try:
                        success = self.smtp_service.send_email(
                            smtp=smtp,
                            to_email=recipient['email'],
                            subject=template.subject,
                            body=template.template,
                            proxy=proxy
                        )
                        if success:
                            success_count += 1
                            mailing_total.labels(status='success').inc()
                        else:
                            mailing_total.labels(status='failure').inc()
                    except Exception as e:
                        logger.error(f"Failed to send email: {str(e)}")
                        mailing_total.labels(status='failure').inc()

                return {
                    'total': len(base),
                    'success': success_count,
                    'failed': len(base) - success_count
                }

        except Exception as e:
            logger.error(f"Mailing failed: {str(e)}")
            mailing_total.labels(status='failure').inc()
            raise 