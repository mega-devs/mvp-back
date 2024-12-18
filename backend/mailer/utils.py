import re
from typing import Tuple, Optional
from email.utils import formataddr

def validate(data, params):
    """Validate that all required parameters are present in data"""
    return all(param in data for param in params)

def validate_email(email):
    """Validate email format"""
    return re.match(r"[^@]+@[^@]+\.[^@]+", email) is not None

def remove_duplicate_lines(file_content):
    """Remove duplicate lines from file content"""
    lines = file_content.split('\n')
    return list(dict.fromkeys(lines))

def process_smtp_line(smtp_input):
    """Process SMTP input line in various formats"""
    try:
        # Try different formats
        formats = [
            lambda x: x.split(':', 3),  # format1: server:port:email:password
            lambda x: (x.split(':', 2)[0], x.split(':', 2)[1], 
                      *x.split(':', 2)[2].rsplit(':', 1)),  # format2: server:email:password:port
            lambda x: x.split(',', 3),  # format3: server,port,email,password
        ]
        
        for fmt in formats:
            try:
                server, port, email, password = fmt(smtp_input)
                if validate_email(email):
                    return server.strip(), port.strip(), email.strip(), password.strip()
            except:
                continue
                
        return None
    except Exception:
        return None

def get_imap_server_and_port(email):
    """Get IMAP server and port based on email domain"""
    domain = email.split('@')[-1].lower()
    
    imap_servers = {
        'outlook.com': ('outlook.office365.com', 993),
        'gmail.com': ('imap.gmail.com', 993),
        'yahoo.com': ('imap.mail.yahoo.com', 993),
    }
    
    return imap_servers.get(domain, (None, None)) 

def validate_template_syntax(template: str) -> Tuple[bool, str]:
    """Validate template HTML syntax"""
    try:
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(template, 'html.parser')
        if not soup.find('body'):
            return False, 'Template must contain <body> tag'
        return True, 'Template syntax is valid'
    except Exception as e:
        return False, f'Template syntax error: {str(e)}'

def clean_html(html: str) -> str:
    """Clean HTML from potentially dangerous elements"""
    from bs4 import BeautifulSoup
    
    soup = BeautifulSoup(html, 'html.parser')
    
    # Remove script tags
    for script in soup.find_all('script'):
        script.decompose()
        
    # Remove on* attributes
    for tag in soup.find_all(True):
        for attr in list(tag.attrs):
            if attr.startswith('on'):
                del tag[attr]
                
    return str(soup)

def format_email_address(name: Optional[str], email: str) -> str:
    """Форматирование email адреса с именем"""
    if name:
        return formataddr((name, email))
    return email

def validate_required_fields(data: dict, required_fields: list) -> bool:
    """Проверка наличия обязательных полей"""
    return all(field in data for field in required_fields)