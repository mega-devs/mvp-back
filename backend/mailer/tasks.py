import asyncio
from celery import shared_task
from django.apps import apps
from .metrics import smtp_check_total, proxy_check_total, celery_tasks_total

# Получаем модели
SMTP = apps.get_model('mailer', 'SMTP')
Proxy = apps.get_model('mailer', 'Proxy')
Template = apps.get_model('mailer', 'Template')
Base = apps.get_model('mailer', 'Base')
Log = apps.get_model('mailer', 'Log')

# Импортируем сервисы с полными путями
from mailer.services.smtp_service import SMTPService
from mailer.services.proxy_service import ProxyService
from mailer.services.mailer_service import MailerService
from mailer.services.file_service import FileService

@shared_task(bind=True, max_retries=3)
def check_smtp_task(self, smtp_id: int, proxy_id: int = None):
    """Задача проверки SMTP сервера"""
    try:
        celery_tasks_total.labels(task_name='check_smtp', status='started').inc()
        smtp = SMTP.objects.get(id=smtp_id)
        proxy = Proxy.objects.get(id=proxy_id) if proxy_id else None
        
        smtp_service = SMTPService()
        success, message = smtp_service.check_smtp(
            smtp.server,
            smtp.port,
            smtp.email,
            smtp.password,
            proxy.to_dict() if proxy else None
        )
        
        smtp.status = 'valid' if success else 'invalid'
        smtp.save()
        
        celery_tasks_total.labels(task_name='check_smtp', status='completed').inc()
        smtp_check_total.labels(status='success' if success else 'failure').inc()
        return {'success': success, 'message': message}
        
    except Exception as e:
        celery_tasks_total.labels(task_name='check_smtp', status='failed').inc()
        self.retry(exc=e, countdown=60)

@shared_task(bind=True, max_retries=3)
def check_proxy_task(self, proxy_id: int):
    """Задача проверки прокси"""
    try:
        proxy = Proxy.objects.get(id=proxy_id)
        proxy_service = ProxyService()
        
        success, message = proxy_service.check_proxy(proxy.to_dict())
        
        proxy.status = 'valid' if success else 'invalid'
        proxy.save()
        
        return {'success': success, 'message': message}
        
    except Exception as e:
        self.retry(exc=e, countdown=60)

def run_async(coro):
    """Вспомогательная функция для запуска асинхронного кода"""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()

@shared_task(bind=True)
def send_mass_mail_task(
    self,
    session: str,
    template_ids: list,
    smtp_ids: list,
    proxy_ids: list = None,
    base_ids: list = None,
    delay: float = 0.3,
    max_workers: int = 5
):
    """Задача массовой рассылки"""
    try:
        mailer_service = MailerService(session)
        results = []
        
        async def process_template(template_id):
            async for result in mailer_service.process_mailing(
                template_id,
                smtp_ids,
                proxy_ids,
                base_ids,
                delay,
                max_workers
            ):
                results.append(result)
        
        for template_id in template_ids:
            run_async(process_template(template_id))
                
        return results
        
    except Exception as e:
        Log.objects.create(
            session=session,
            type='mass_mailing',
            text=f"Error: {str(e)}",
            status='error'
        )
        raise self.retry(exc=e, countdown=300) 

@shared_task
def cleanup_temp_files():
    """Задача очистки временных файлов"""
    FileService.cleanup_temp_files()

@shared_task
def archive_old_logs():
    """Задача архивации старых логов"""
    FileService.archive_logs()