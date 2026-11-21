# Synthetic test fixture — do not use real credentials
API_KEY = "EXAMPLE_NOT_A_REAL_SECRET_123456789"
import subprocess
subprocess.run(["echo", "safe test fixture"])
