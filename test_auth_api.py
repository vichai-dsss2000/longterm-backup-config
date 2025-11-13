#!/usr/bin/env python3
"""
Test authentication API endpoints
"""
import requests
import json

BASE_URL = "http://localhost:8000"

def test_login():
    """Test login endpoint"""
    url = f"{BASE_URL}/api/auth/login"
    data = {
        "username": "admin",
        "password": "admin123"
    }
    
    print(f"Testing login at {url}")
    print(f"Request data: {data}")
    
    try:
        response = requests.post(url, json=data)
        print(f"Status code: {response.status_code}")
        print(f"Response headers: {dict(response.headers)}")
        
        if response.status_code == 200:
            response_data = response.json()
            print(f"Login successful!")
            print(f"Access token: {response_data['access_token'][:50]}...")
            
            # Test /me endpoint
            test_me_endpoint(response_data['access_token'])
        else:
            print(f"Login failed: {response.text}")
            
    except Exception as e:
        print(f"Error: {e}")

def test_me_endpoint(token):
    """Test /me endpoint with token"""
    url = f"{BASE_URL}/api/auth/me"
    headers = {
        "Authorization": f"Bearer {token}"
    }
    
    print(f"\nTesting /me endpoint at {url}")
    
    try:
        response = requests.get(url, headers=headers)
        print(f"Status code: {response.status_code}")
        
        if response.status_code == 200:
            print(f"User info: {response.json()}")
        else:
            print(f"Failed: {response.text}")
            
    except Exception as e:
        print(f"Error: {e}")

def test_schedules_endpoint(token):
    """Test schedules endpoint with token"""
    url = f"{BASE_URL}/api/schedules/"
    headers = {
        "Authorization": f"Bearer {token}"
    }
    
    print(f"\nTesting schedules endpoint at {url}")
    
    try:
        response = requests.get(url, headers=headers)
        print(f"Status code: {response.status_code}")
        
        if response.status_code == 200:
            schedules = response.json()
            print(f"Found {len(schedules)} schedules")
            for schedule in schedules:
                print(f"  - {schedule.get('policy_name', 'Unknown')}")
        else:
            print(f"Failed: {response.text}")
            
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    print("Testing authentication API...")
    test_login()