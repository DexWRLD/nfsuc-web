"""Explicitly obtain only the Phase 72 reviewed engine, outside the repository.
No npm install, lifecycle script, runtime registry update or game-asset copy.
"""
import argparse,base64,hashlib,io,json,tarfile,urllib.request
from pathlib import Path
PACKAGE='https://registry.npmjs.org/@alexaltea/unicorn-js/-/unicorn-js-2.1.4.tgz'
INTEGRITY='UAml23tgHyXEuP2A7Y50qDCNYMIRHJobsjlhetPRrtH+PXg0+BNAyvPQEKoCd+VHAF1nDfPHE4yJCqSLVtOrXA=='
ENGINE_SHA='643adbbb0c77eadb71182f116c9da0860814221a25194dac3ed561589929ef6d'
def prepare(destination):
 root=Path(__file__).resolve().parents[1]
 if destination.resolve().is_relative_to(root):raise ValueError('Engine binaries must stay outside Git repository')
 raw=urllib.request.urlopen(PACKAGE,timeout=30).read()
 if base64.b64encode(hashlib.sha512(raw).digest()).decode()!=INTEGRITY:raise ValueError('Package integrity mismatch')
 archive=tarfile.open(fileobj=io.BytesIO(raw),mode='r:gz');engine=archive.extractfile('package/dist/unicorn_x86.js').read()
 if hashlib.sha256(engine).hexdigest()!=ENGINE_SHA:raise ValueError('Engine SHA mismatch')
 destination.mkdir(parents=True,exist_ok=True)
 for source,name in [('package/dist/unicorn_x86.js','unicorn_x86.js'),('package/LICENSE','LICENSE'),('package/package.json','package.json')]:
  (destination/name).write_bytes(archive.extractfile(source).read())
 print(json.dumps(dict(engine=str(destination/'unicorn_x86.js'),version='2.1.4',sha256=ENGINE_SHA,license='GPL-2.0',productionDelivery=False)))
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('destination',type=Path);a=p.parse_args();prepare(a.destination)
