from pathlib import Path
import tempfile
with tempfile.TemporaryDirectory() as d:
    p=Path(d)
    files=[]
    for i in range(60):
        f=p/f"document_{i}.txt"
        f.write_text("harmless test")
        files.append(f)
    for f in files:
        f.write_text("harmless modified test")
    for i,f in enumerate(files):
        f.rename(p/f"renamed_{i}.txt")
print("Harmless file-burst simulation complete.")
