import functools
from django.core.cache import cache
import logging

logger = logging.getLogger('mailer')

def make_key(prefix, id):
    """Создание ключа кэша"""
    return f"{prefix}:{id}"

def cache_result(cache_key, timeout=None):
    """
    Декоратор для кэширования результатов функции
    """
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Формируем ключ кэша
            key = f"{cache_key}:{':'.join(str(arg) for arg in args)}"
            if kwargs:
                key += f":{':'.join(f'{k}={v}' for k,v in kwargs.items())}"
            
            # Пробуем получить из кэша
            result = cache.get(key)
            if result is not None:
                logger.debug(f"Cache hit for key: {key}")
                return result
                
            # Если нет в кэше - вычисляем
            result = func(*args, **kwargs)
            cache.set(key, result, timeout)
            logger.debug(f"Cache miss for key: {key}")
            return result
            
        return wrapper
    return decorator

def invalidate_cache(cache_key, *args, **kwargs):
    """
    Инвалидация кэша для конкретного ключа
    """
    key = f"{cache_key}:{':'.join(str(arg) for arg in args)}"
    if kwargs:
        key += f":{':'.join(f'{k}={v}' for k,v in kwargs.items())}"
    cache.delete(key)
    logger.debug(f"Cache invalidated for key: {key}")

def bulk_cache_operations(items, operation_func, prefix, chunk_size=1000):
    """Пакетные операции с кэшем"""
    for i in range(0, len(items), chunk_size):
        chunk = items[i:i + chunk_size]
        pipe = cache.client.pipeline()
        
        for item in chunk:
            key = make_key(prefix, item.id)
            operation_func(pipe, key, item)
            
        pipe.execute() 