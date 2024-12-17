from channels.generic.websocket import AsyncWebsocketConsumer
import json
import logging
import asyncio
import concurrent.futures
from typing import List

logger = logging.getLogger('mailer')

class MailerConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        await self.accept()
        logger.info(f'WebSocket connection established: {self.channel_name}')

    async def disconnect(self, close_code):
        logger.info(f'WebSocket connection closed: {self.channel_name}')
        pass

    async def receive(self, text_data):
        try:
            data = json.loads(text_data)
            message_type = data.get('type')
            
            if message_type == 'check_smtps':
                await self.handle_check_smtps(data)
            elif message_type == 'check_imaps':
                await self.handle_check_imaps(data)
            elif message_type == 'check_proxy':
                await self.handle_check_proxy(data)
            elif message_type == 'mailing':
                await self.handle_mailing(data)
            elif message_type == 'mass_mailing':
                await self.handle_mass_mailing(data)
            elif message_type == 'template_check':
                await self.handle_template_check(data)
            else:
                logger.warning(f'Unknown message type received: {message_type}')
                
        except json.JSONDecodeError:
            logger.error('Invalid JSON received')
        except Exception as e:
            logger.error(f'Error processing WebSocket message: {str(e)}')

    async def send_progress(self, event_type, current, total, errors=None):
        await self.send(text_data=json.dumps({
            'type': event_type,
            'progress': (current / total) * 100,
            'current': current,
            'total': total,
            'errors': errors
        }))

    async def handle_check_smtps(self, data):
        """Handle SMTP check progress"""
        try:
            session = data.get('session')
            smtp_ids = data.get('smtp_ids', [])
            proxy_ids = data.get('proxy_ids', [])
            
            total = len(smtp_ids)
            current = 0
            
            valid_emails, invalid_emails = await self.check_smtps_async(
                session, smtp_ids, proxy_ids
            )
            
            await self.send_progress('smtp_check', len(valid_emails), total, {
                'valid': valid_emails,
                'invalid': invalid_emails
            })
            
        except Exception as e:
            logger.error(f'Error in handle_check_smtps: {str(e)}')
            await self.send(text_data=json.dumps({
                'type': 'error',
                'message': str(e)
            }))

    async def handle_check_imaps(self, data):
        """Handle IMAP check progress"""
        try:
            session = data.get('session')
            imap_ids = data.get('imap_ids', [])
            
            total = len(imap_ids)
            current = 0
            
            results = await self.check_imaps_async(session, imap_ids)
            
            await self.send_progress('imap_check', 
                len(results['valid']), total, results)
            
        except Exception as e:
            logger.error(f'Error in handle_check_imaps: {str(e)}')
            await self.send(text_data=json.dumps({
                'type': 'error',
                'message': str(e)
            }))

    async def handle_check_proxy(self, data):
        """Handle proxy check progress"""
        try:
            session = data.get('session')
            proxy_ids = data.get('proxy_ids', [])
            
            total = len(proxy_ids)
            current = 0
            
            valid_proxies, invalid_proxies = await self.check_proxies_async(
                session, proxy_ids
            )
            
            await self.send_progress('proxy_check', len(valid_proxies), total, {
                'valid': valid_proxies,
                'invalid': invalid_proxies
            })
            
        except Exception as e:
            logger.error(f'Error in handle_check_proxy: {str(e)}')
            await self.send(text_data=json.dumps({
                'type': 'error',
                'message': str(e)
            }))

    async def handle_mailing(self, data):
        """Handle mailing progress"""
        try:
            session = data.get('session')
            sending_limit = data.get('sending_limit', 200)
            threads_number = data.get('threads_number', 5)
            delay = data.get('delay', 0.3)
            
            sent_count = 0
            failed_count = 0
            
            async for result in self.mailing_async(session, sending_limit, threads_number, delay):
                if result['success']:
                    sent_count += 1
                else:
                    failed_count += 1
                    
                await self.send_progress('mailing', sent_count, sending_limit, {
                    'sent': sent_count,
                    'failed': failed_count
                })
                
        except Exception as e:
            logger.error(f'Error in handle_mailing: {str(e)}')
            await self.send(text_data=json.dumps({
                'type': 'error',
                'message': str(e)
            }))

    async def handle_mass_mailing(self, data):
        """Handle mass mailing progress"""
        try:
            session = data.get('session')
            sending_limit = data.get('sending_limit', 200)
            threads_number = data.get('threads_number', 5)
            delay = data.get('delay', 0.3)
            emails_per_smtp = data.get('emails_per_smtp', 3)
            
            mailing_data = {
                'sending_limit': sending_limit,
                'threads_number': threads_number,
                'delay': delay,
                'emails_per_smtp': emails_per_smtp
            }
            
            # Start mailing in background
            loop = asyncio.get_event_loop()
            success = await loop.run_in_executor(
                None,
                MailerService.start_mass_mailing,
                session,
                mailing_data
            )
            
            if success:
                await self.send(text_data=json.dumps({
                    'type': 'mailing_complete',
                    'status': 'success'
                }))
            else:
                await self.send(text_data=json.dumps({
                    'type': 'mailing_complete',
                    'status': 'error'
                }))
                
        except Exception as e:
            logger.error(f'Error in handle_mass_mailing: {str(e)}')
            await self.send(text_data=json.dumps({
                'type': 'error',
                'message': str(e)
            }))

    async def handle_template_check(self, data):
        """Handle template validation"""
        try:
            template = data.get('template', '')
            test_data = data.get('test_data')
            
            # Validate template syntax
            syntax_valid, syntax_message = utils.validate_template_syntax(template)
            if not syntax_valid:
                await self.send(text_data=json.dumps({
                    'type': 'template_check',
                    'valid': False,
                    'message': syntax_message
                }))
                return
                
            # Validate template placeholders
            valid, message = MailerService.validate_template(template, test_data)
            
            await self.send(text_data=json.dumps({
                'type': 'template_check',
                'valid': valid,
                'message': message
            }))
            
        except Exception as e:
            logger.error(f'Error in handle_template_check: {str(e)}')
            await self.send(text_data=json.dumps({
                'type': 'error',
                'message': str(e)
            }))

    async def check_smtps_async(self, session: str, smtp_ids: List[str], proxy_ids: List[str]):
        """Async wrapper for SMTP check"""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None, 
            MailerService.check_smtps,
            session,
            smtp_ids,
            proxy_ids
        )

    async def check_proxies_async(self, session: str, proxy_ids: List[str]):
        """Async wrapper for proxy check"""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None,
            MailerService.check_proxies,
            session,
            proxy_ids
        )

    async def mailing_async(self, session: str, sending_limit: int, threads_number: int, delay: float):
        """Async generator for mailing progress"""
        loop = asyncio.get_event_loop()
        queue = asyncio.Queue()
        
        async def process_results():
            while True:
                try:
                    result = await queue.get()
                    yield result
                    queue.task_done()
                except asyncio.CancelledError:
                    break

        def mailing_callback(future):
            loop.call_soon_threadsafe(queue.put_nowait, future.result())

        # Start mailing in thread pool
        futures = []
        with concurrent.futures.ThreadPoolExecutor() as pool:
            for _ in range(threads_number):
                future = loop.run_in_executor(
                    pool,
                    MailerService.send_batch,
                    session,
                    sending_limit // threads_number,
                    delay
                )
                future.add_done_callback(mailing_callback)
                futures.append(future)

        async for result in process_results():
            yield result

        await queue.join()
