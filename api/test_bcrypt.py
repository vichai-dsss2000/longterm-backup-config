import bcrypt

stored = "$2b$12$MsE2o2PB07OntEqqw.fFeOJUZcH2qS.j9JrmlQcBASs7D6my5i.Ia"
print('bcrypt module:', bcrypt)
try:
    ok = bcrypt.checkpw(b'admin123', stored.encode())
    print('checkpw result:', ok)
except Exception as e:
    print('checkpw raised:', e)

print('bcrypt version attr exists?', hasattr(bcrypt, '__about__'))
try:
    print('bcrypt.__about__:', getattr(bcrypt, '__about__', None))
except Exception as e:
    print('bcrypt.__about__ access error:', e)
