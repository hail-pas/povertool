from django.test import TestCase

# Create your tests here.
import os
import requests
from unittest import TestCase, main

import django
from django.urls import reverse

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'povertool.settings')
django.setup()


# UnitTest测试
class APITestCase(TestCase):
    app_label = 'api'
    address = "http://127.0.0.1:8000"
    headers = {}

    def get_url(self, viewname, *args, **kwargs):
        return f"{self.address}{reverse(f'{self.app_label}:{viewname}', args=args, kwargs=kwargs)}"


class ToolsTest(APITestCase):
    def setUp(self):
        """
        prepare before test; such as: init redis、set common data
        :return:
        """
        pass

    def test_login(self):
        """验证登录"""
        url = self.get_url('login')
        data = {
            'phone': '18000000000',
            'password': '2021LearnForever',
        }

        response = requests.post(url, headers=self.headers, data=data)
        self.assertEqual(response.status_code, 200)

    def tearDown(self):
        """
        aftercase such as: close redis、file
        :return:
        """
        pass


# PyTest
import pytest


@pytest.mark.asyncio
async def test_login():
    pass

if __name__=="__main__":
    main()