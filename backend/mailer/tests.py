from django.test import TestCase
from django.contrib.auth.models import User
from rest_framework.test import APIClient
from rest_framework import status
from .models import *
import json

class MailerTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            username='testuser',
            password='testpass123'
        )
        self.session = Session.objects.create(name='test_session')
        
    def test_login(self):
        response = self.client.post('/api/login', {
            'name': 'testuser',
            'password': 'testpass123'
        })
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('token', response.data)
        
    def test_add_session(self):
        # First login to get token
        response = self.client.post('/api/login', {
            'name': 'testuser',
            'password': 'testpass123'
        })
        token = response.data['token']
        
        # Test adding session
        response = self.client.post('/api/session/add', {
            'token': token,
            'name': 'new_session'
        })
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(Session.objects.filter(name='new_session').exists())
        
    def test_process_smtp_material(self):
        smtp_data = "smtp.gmail.com:587:test@gmail.com:password123"
        result = self.client.post('/api/input/material', {
            'token': self.token,
            'session': 'test_session',
            'type': 'smtps',
            'file': smtp_data
        })
        self.assertEqual(result.status_code, status.HTTP_200_OK)
        self.assertTrue(SMTP.objects.filter(email='test@gmail.com').exists())

