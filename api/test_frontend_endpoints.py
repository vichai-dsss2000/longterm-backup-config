"""Test all API endpoints used by the frontend.

This script logs in using the test admin user, obtains a JWT token,
and issues requests to each endpoint that the frontend calls. It prints
HTTP status codes and a short summary of the response.

Run from repository root with the api venv activated. Example:
  Set-Location '...\longterm-backup-config\api'
  . .\.venv\Scripts\Activate.ps1
  python test_frontend_endpoints.py
"""
import requests
from urllib.parse import urljoin
import sys

BASE = 'http://127.0.0.1:8000/api'

def login(username='admin', password='admin123'):
    url = urljoin(BASE, 'auth/login')
    r = requests.post(url, json={'username': username, 'password': password}, timeout=10)
    return r

def call(method, path, token=None, **kwargs):
    url = urljoin(BASE + '/', path.lstrip('/'))
    headers = kwargs.pop('headers', {})
    if token:
        headers['Authorization'] = f'Bearer {token}'
    try:
        r = requests.request(method, url, headers=headers, timeout=10, **kwargs)
        summary = r.text[:400].replace('\n',' ')
        print(f"{method.upper():6} {path:35} -> {r.status_code:3}  {summary}")
        return r
    except Exception as e:
        print(f"{method.upper():6} {path:35} -> EXC  {e}")
        return None


def main():
    print('Logging in as admin...')
    r = login()
    if r is None:
        print('Login request failed (no response)')
        sys.exit(1)
    if r.status_code != 200:
        print('Login failed:', r.status_code, r.text)
        sys.exit(1)

    data = r.json()
    token = data.get('access_token') or data.get('accessToken')
    if not token:
        print('No access token in login response:', data)
        sys.exit(1)

    print('Login OK, token length:', len(token))

    endpoints = [
        ('get', '/auth/me'),
        ('get', '/devices/'),
        ('get', '/devices/1'),
        ('get', '/devices/types'),
        ('post', '/devices/1/test-connection'),
        ('get', '/devices/1/backup-history'),
        ('get', '/templates/'),
        ('get', '/templates/1'),
        ('post', '/templates/1/validate'),
        ('get', '/templates/by-device-type/1'),
        ('get', '/schedules/'),
        ('get', '/schedules/1'),
        ('get', '/schedules/categories'),
        ('get', '/backups/'),
        ('get', '/backups/recent'),
        ('get', '/backups/stats'),
        ('get', '/backups/1/download'),
    ]

    for method, path in endpoints:
        if method.lower() == 'get':
            call('get', path, token=token)
        elif method.lower() == 'post':
            # send an empty json for POSTs that expect body
            call('post', path, token=token, json={})

    print('Done')


if __name__ == '__main__':
    main()
