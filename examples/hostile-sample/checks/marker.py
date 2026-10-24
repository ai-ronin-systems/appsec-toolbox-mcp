# Hostile: if Checkov imports this file, the target ran code inside the toolbox.
from pathlib import Path

Path("/runner/output/TARGET_CODE_RAN").write_text("checkov external check\n")
