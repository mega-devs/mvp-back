import bleach
import re
import logging
from typing import Any, Dict, List, Optional
from django.core.exceptions import ValidationError
from django.utils.html import escape

logger = logging.getLogger('mailer')

class SecurityUtils:
    ALLOWED_TAGS = [
        'p', 'br', 'strong', 'em', 'u', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
        'div', 'span', 'a', 'img', 'table', 'tr', 'td', 'th', 'tbody', 'thead'
    ]
    
    ALLOWED_ATTRIBUTES = {
        'a': ['href', 'title', 'target'],
        'img': ['src', 'alt', 'title', 'width', 'height'],
        '*': ['class', 'style']
    }
    
    ALLOWED_STYLES = [
        'color', 'font-family', 'font-size', 'font-weight', 'text-align',
        'margin', 'padding', 'border', 'background-color'
    ]

    @staticmethod
    def sanitize_html(content: str) -> str:
        """Санитизация HTML контента"""
        try:
            clean_html = bleach.clean(
                content,
                tags=SecurityUtils.ALLOWED_TAGS,
                attributes=SecurityUtils.ALLOWED_ATTRIBUTES,
                styles=SecurityUtils.ALLOWED_STYLES,
                strip=True
            )
            return clean_html
        except Exception as e:
            logger.error(f"HTML sanitization failed: {str(e)}")
            return escape(content)

    @staticmethod
    def validate_email_template(template: Dict) -> Dict:
        """Валидация шаблона email"""
        required_fields = ['subject', 'body']
        for field in required_fields:
            if field not in template:
                raise ValidationError(f"Missing required field: {field}")
            
        # Санитизация HTML в теле письма
        template['body'] = SecurityUtils.sanitize_html(template['body'])
        
        # Проверка на вредоносные конструкции
        SecurityUtils.check_malicious_content(template['body'])
        
        return template

    @staticmethod
    def check_malicious_content(content: str) -> None:
        """Проверка на вредоносный контент"""
        patterns = [
            r'<script.*?>.*?</script>',
            r'javascript:',
            r'onerror=',
            r'onload=',
            r'eval\(',
            r'document\.cookie',
            r'alert\(',
        ]
        
        for pattern in patterns:
            if re.search(pattern, content, re.IGNORECASE):
                raise ValidationError(f"Detected potentially malicious content: {pattern}")

    @staticmethod
    def validate_file_upload(file_obj: Any) -> None:
        """Валидация загружаемых файлов"""
        # Проверка размера файла
        if file_obj.size > 10 * 1024 * 1024:  # 10MB
            raise ValidationError("File size exceeds limit")
            
        # Проверка расширения
        allowed_extensions = ['.txt', '.csv', '.json']
        ext = file_obj.name.lower().split('.')[-1]
        if f'.{ext}' not in allowed_extensions:
            raise ValidationError(f"File type not allowed: {ext}")
            
        # Проверка содержимого первых байтов
        content_start = file_obj.read(512).decode('utf-8', errors='ignore')
        file_obj.seek(0)
        
        # Проверка на исполняемый код
        if re.search(r'<\?php|#!/|import os|system\(', content_start):
            raise ValidationError("File contains potentially dangerous content")

    @staticmethod
    def validate_headers(headers: Dict) -> Dict:
        """Валидация HTTP заголовков"""
        sanitized = {}
        for key, value in headers.items():
            # Удаляем потенциально опасные заголовки
            if key.lower() in ['cookie', 'authorization']:
                continue
                
            # Санитизация значений
            if isinstance(value, str):
                sanitized[key] = SecurityUtils.sanitize_header_value(value)
                
        return sanitized

    @staticmethod
    def sanitize_header_value(value: str) -> str:
        """Санитизация значений заголовков"""
        # Удаляем управляющие символы и переносы строк
        return re.sub(r'[\x00-\x1f\x7f]', '', value) 