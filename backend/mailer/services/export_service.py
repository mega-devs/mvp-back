import csv
import io
import logging
from typing import List, Dict
from ..models import Base, SMTP, Proxy, Log

logger = logging.getLogger('mailer')

class ExportService:
    @staticmethod
    def export_to_csv(data: List[Dict], fields: List[str]) -> str:
        """Экспорт данных в CSV формат"""
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=fields)
        writer.writeheader()
        writer.writerows(data)
        return output.getvalue()

    @staticmethod
    def export_bases(session: str) -> str:
        """Экспорт базы email адресов"""
        bases = Base.objects.filter(session=session).values('first', 'last', 'email')
        return ExportService.export_to_csv(
            bases,
            ['first', 'last', 'email']
        )

    @staticmethod
    def export_smtp(session: str) -> str:
        """Экспорт SMTP серверов"""
        smtps = SMTP.objects.filter(session=session).values(
            'server', 'port', 'email', 'password', 'status'
        )
        return ExportService.export_to_csv(
            smtps,
            ['server', 'port', 'email', 'password', 'status']
        )

    @staticmethod
    def export_proxy(session: str) -> str:
        """Экспорт прокси"""
        proxies = Proxy.objects.filter(session=session).values('ip', 'port', 'status')
        return ExportService.export_to_csv(
            proxies,
            ['ip', 'port', 'status']
        )

    @staticmethod
    def export_logs(session: str) -> str:
        """Экспорт логов"""
        logs = Log.objects.filter(session=session).values(
            'created_at', 'type', 'text', 'status'
        )
        return ExportService.export_to_csv(
            logs,
            ['created_at', 'type', 'text', 'status']
        ) 