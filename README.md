# Mailer System
A mass email sending system with SMTP, proxy and template support.


## Features
- SMTP server management
- SOCKS5 proxy support  
- HTML email templates
- Mass mailing
- WebSocket notifications
- Async tasks
- API interface
- Data export/import


## Tech Stack
- Python 3.11
- Django 4.2
- Django REST Framework
- Celery
- Redis
- MySQL
- WebSocket (Channels)
- Docker


## Quick Start
1. Clone repository:
```
git clone https://github.com/username/mailer-system.git
cd mailer-system
```

2. Build & Run with Docker Compose:
```
docker-compose up --build -d
```

3. Access web interface at:
```
http://localhost:8000
```