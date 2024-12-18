import os
import magic
import logging
import shutil
from datetime import datetime, timedelta
from django.conf import settings
from django.core.files.storage import default_storage
from django.core.files.base import ContentFile
from ..models import Log

logger = logging.getLogger('mailer')

class FileService:
    ALLOWED_MIME_TYPES = {
        'text/plain': ['.txt', '.csv'],
        'text/csv': ['.csv'],
        'application/vnd.ms-excel': ['.csv', '.xls'],
        'application/json': ['.json'],
    }
    
    MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
    TEMP_DIR = os.path.join(settings.MEDIA_ROOT, 'temp')
    ARCHIVE_DIR = os.path.join(settings.MEDIA_ROOT, 'archives')

    @classmethod
    def setup_directories(cls):
        """Создание необходимых директорий"""
        os.makedirs(cls.TEMP_DIR, exist_ok=True)
        os.makedirs(cls.ARCHIVE_DIR, exist_ok=True)

    @classmethod
    def validate_file(cls, file_obj):
        """Валидация загружаемого файла"""
        if file_obj.size > cls.MAX_FILE_SIZE:
            raise ValueError(f"File size exceeds {cls.MAX_FILE_SIZE/1024/1024}MB")

        mime = magic.from_buffer(file_obj.read(1024), mime=True)
        file_obj.seek(0)

        if mime not in cls.ALLOWED_MIME_TYPES:
            raise ValueError(f"Unsupported file type: {mime}")

        ext = os.path.splitext(file_obj.name)[1].lower()
        if ext not in cls.ALLOWED_MIME_TYPES[mime]:
            raise ValueError(f"Invalid file extension for type {mime}")

        return True

    @classmethod
    def save_temp_file(cls, content, prefix='temp'):
        """Сохранение временного файла"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"{prefix}_{timestamp}.txt"
        path = os.path.join(cls.TEMP_DIR, filename)
        
        with open(path, 'w', encoding='utf-8') as f:
            f.write(content)
            
        return path

    @classmethod
    def cleanup_temp_files(cls, max_age_hours=24):
        """Очистка старых временных файлов"""
        cutoff = datetime.now() - timedelta(hours=max_age_hours)
        
        for filename in os.listdir(cls.TEMP_DIR):
            filepath = os.path.join(cls.TEMP_DIR, filename)
            file_modified = datetime.fromtimestamp(os.path.getmtime(filepath))
            
            if file_modified < cutoff:
                try:
                    os.remove(filepath)
                    logger.info(f"Removed old temp file: {filename}")
                except Exception as e:
                    logger.error(f"Error removing temp file {filename}: {str(e)}")

    @classmethod
    def archive_logs(cls, days_old=7):
        """Архивация старых логов"""
        cutoff = datetime.now() - timedelta(days=days_old)
        logs = Log.objects.filter(created_at__lt=cutoff)
        
        if not logs.exists():
            return
            
        timestamp = datetime.now().strftime('%Y%m%d')
        archive_name = f"logs_{timestamp}.txt"
        archive_path = os.path.join(cls.ARCHIVE_DIR, archive_name)
        
        with open(archive_path, 'w', encoding='utf-8') as f:
            for log in logs:
                f.write(f"{log.created_at} [{log.type}] {log.text}\n")
                
        # Удаляем заархивированные логи
        logs.delete()
        logger.info(f"Archived {logs.count()} logs to {archive_name}")

    @classmethod
    def compress_archive(cls, archive_path):
        """Сжатие архива"""
        try:
            import gzip
            with open(archive_path, 'rb') as f_in:
                with gzip.open(f"{archive_path}.gz", 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
            os.remove(archive_path)
            logger.info(f"Compressed archive: {archive_path}")
        except Exception as e:
            logger.error(f"Error compressing archive {archive_path}: {str(e)}") 