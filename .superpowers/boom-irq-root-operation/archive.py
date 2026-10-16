import os,sys,tarfile
from pathlib import Path
base=Path('/root/fanzehui/boom-irq-runtime-gate-20261017')
os.chdir(base)
names=('gate-output','gpio-cache','state','logs','control','ready.json','source-freeze.json','project-files.json','original-source-files.json','original-artifact-files.json','preparation-ready.initial.json','final-control-pins.json')
with tarfile.open(fileobj=sys.stdout.buffer,mode='w|gz') as archive:
 for name in names:
  if (base/name).exists():archive.add(name,arcname=name)
