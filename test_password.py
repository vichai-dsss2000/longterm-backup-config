import bcrypt
from passlib.context import CryptContext

# Test password verification
password = "admin123"
stored_hash = "$2b$12$StPJq17pP1mSMlCfZy.86.XFhTgJ3hcrqF2uafLlIZEMFZHlmM0Wy"

# Test with bcrypt directly
print("Testing with bcrypt directly:")
print(f"Password matches: {bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8'))}")

# Test with passlib (same as the app uses)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
print("\nTesting with passlib (same as app):")
print(f"Password matches: {pwd_context.verify(password, stored_hash)}")

# Test creating a new hash
print("\nCreating new hash for comparison:")
new_hash = pwd_context.hash(password)
print(f"New hash: {new_hash}")
print(f"New hash verifies: {pwd_context.verify(password, new_hash)}")