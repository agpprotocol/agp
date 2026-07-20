from pathlib import Path
import subprocess, sys
ROOT=Path(__file__).resolve().parent
subprocess.run([sys.executable,str(ROOT/"tools/run_conformance.py")],check=True)
subprocess.run([sys.executable,str(ROOT/"signed/tools/run_signed_conformance.py")],check=True)
subprocess.run([sys.executable,str(ROOT/"transparency/tools/run_transparency.py")],check=True)
print("AGP v0.5 COMPLETE: semantics, signatures and transparency passed")
