import sqlite3
from pathlib import Path
from passlib.context import CryptContext

p = Path(__file__).parent / 'longterm_backup_config.db'
print('DB path:', p)
conn = sqlite3.connect(p)
cur = conn.cursor()
cur.execute("SELECT id,username,email,password_hash,is_active,is_admin FROM users WHERE username='admin'")
row = cur.fetchone()
print('row:', row)
if not row:
    print('admin user not found')
else:
    pwd_hash = row[3]
    print('stored hash:', pwd_hash[:60])
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto", bcrypt__rounds=12, bcrypt__ident="2b")
    plain = 'admin123'
    pw_bytes = plain.encode('utf-8')[:72]
    pw_trunc = pw_bytes.decode('utf-8','ignore')
    print('pw_trunc repr:', repr(pw_trunc))
    try:
        ok = pwd_context.verify(pw_trunc, pwd_hash)
        print('verify result:', ok)
    except Exception as e:
        print('verify raised:', e)
conn.close()
