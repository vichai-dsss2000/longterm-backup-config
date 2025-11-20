import importlib
import sys

modules = ["fastapi", "pydantic", "pydantic_core", "netmiko"]
print(f"Python: {sys.version.splitlines()[0]}")
ok = True
for m in modules:
    try:
        mod = importlib.import_module(m)
        ver = getattr(mod, "__version__", getattr(mod, "VERSION", "n/a"))
        print(f"{m}: {ver}")
    except Exception as e:
        print(f"ERR importing {m}: {e}")
        ok = False

if not ok:
    sys.exit(2)
print("SMOKE_CHECK: OK")
