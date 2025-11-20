"""Test API endpoints using FastAPI TestClient (in-process).

This avoids running a separate uvicorn process. It imports `main_simple.app`
and uses TestClient to make requests.
"""
from starlette.testclient import TestClient
# Use the full app (main.py) so all routers (templates, schedules, backups) are registered
from main import app

client = TestClient(app)

def login(username='admin', password='admin123'):
    r = client.post('/api/auth/login', json={'username': username, 'password': password})
    return r

def call(method, path, token=None, **kwargs):
    headers = kwargs.pop('headers', {})
    if token:
        headers['Authorization'] = f'Bearer {token}'
    r = client.request(method, path, headers=headers, **kwargs)
    summary = r.text[:400].replace('\n',' ')
    print(f"{method.upper():6} {path:35} -> {r.status_code:3}  {summary}")
    return r

def main():
    print('Logging in as admin...')
    r = login()
    print('Login status:', r.status_code)
    if r.status_code != 200:
        print('Login failed:', r.status_code, r.text)
        return
    data = r.json()
    token = data.get('access_token')
    print('Token length:', len(token))

    endpoints = [
        ('get', '/api/auth/me'),
        ('get', '/api/devices/'),
        ('get', '/api/devices/1'),
        ('get', '/api/devices/types'),
        ('post', '/api/devices/1/test-connection'),
        ('get', '/api/devices/1/backup-history'),
        ('get', '/api/templates/'),
        ('get', '/api/templates/1'),
        ('post', '/api/templates/1/validate'),
        # route is /device-type/{id} in template_router
        ('get', '/api/templates/device-type/1'),
        ('get', '/api/schedules/'),
        ('get', '/api/schedules/1'),
        ('get', '/api/schedules/categories'),
        ('get', '/api/backups/'),
        ('get', '/api/backups/recent'),
        ('get', '/api/backups/stats'),
        ('get', '/api/backups/1/download'),
    ]

    for method, path in endpoints:
        if method == 'get':
            call('get', path, token=token)
        else:
            call('post', path, token=token, json={})

if __name__ == '__main__':
    main()
