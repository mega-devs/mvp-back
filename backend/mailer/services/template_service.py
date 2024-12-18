import re
import logging
from typing import Dict, List, Tuple
from bs4 import BeautifulSoup
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from ..utils import format_email_address

logger = logging.getLogger('mailer')

class TemplateService:
    @staticmethod
    def validate_template(template: Dict) -> Tuple[bool, str]:
        """Валидация шаблона письма"""
        try:
            required_fields = ['subject', 'from', 'body']
            for field in required_fields:
                if field not in template:
                    return False, f"Missing {field} in template"

            # Проверка HTML
            soup = BeautifulSoup(template['body'], 'html.parser')
            
            # Удаление опасных тегов и атрибутов
            for tag in soup.find_all(True):
                if tag.name in ['script', 'iframe', 'object', 'embed']:
                    tag.decompose()
                    
                for attr in list(tag.attrs):
                    if attr.startswith('on'):
                        del tag[attr]

            return True, "Template is valid"

        except Exception as e:
            logger.error(f"Template validation failed: {str(e)}")
            return False, str(e)

    @staticmethod
    def prepare_email(
        template: Dict,
        from_email: str,
        to_email: str,
        from_name: str = None,
        to_name: str = None
    ) -> MIMEMultipart:
        """Подготовка email сообщения"""
        msg = MIMEMultipart('alternative')
        msg['Subject'] = template['subject']
        msg['From'] = format_email_address(from_name, from_email) if from_name else from_email
        msg['To'] = format_email_address(to_name, to_email) if to_name else to_email

        # Добавляем текст и HTML версии
        text_part = MIMEText(
            BeautifulSoup(template['body'], 'html.parser').get_text(), 
            'plain'
        )
        html_part = MIMEText(template['body'], 'html')

        msg.attach(text_part)
        msg.attach(html_part)

        return msg

    @staticmethod
    def replace_placeholders(template: Dict, data: Dict) -> Dict:
        """Замена плейсхолдеров в шаблоне"""
        result = template.copy()
        
        for key, value in data.items():
            placeholder = f"{{{key}}}"
            result['subject'] = result['subject'].replace(placeholder, str(value))
            result['body'] = result['body'].replace(placeholder, str(value))

        return result 