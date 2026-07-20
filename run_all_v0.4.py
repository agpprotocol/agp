from pathlib import Path
import subprocess,sys
R=Path(__file__).resolve().parent
subprocess.run([sys.executable,str(R/'tools/run_conformance.py')],check=True)
subprocess.run([sys.executable,str(R/'signed/tools/run_signed_conformance.py')],check=True)
print('AGP v0.4 COMPLETE: semantic and signed conformance passed')
