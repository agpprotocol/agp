from pathlib import Path
import subprocess, sys
ROOT=Path(__file__).resolve().parent
subprocess.run([sys.executable,str(ROOT/"run_all_v0.5.py")],check=True)
subprocess.run([sys.executable,str(ROOT/"benchmark/tools/run_benchmark.py")],check=True)
print("AGP BENCHMARK COMPLETE")
