#!/usr/bin/env bash
# Independent, read-only original ARM probes; no GUI startup or firmware writes.
set -euo pipefail
cd "$(dirname "$0")"
PY=/home/starlight/projects/rav4-radio/ca01-development-kit/.venv/bin/python
mkdir -p results
"$PY" probe_type_txt_fallback.py > results/type-fallback.log
"$PY" probe_scene_after_missing_type.py > results/scene-after-type-fallback.log
"$PY" probe_scene_with_pool_config.py > results/scene-after-pool-config.log
"$PY" probe_task10_real_waitinit.py > results/task10-real-waitinit.log
"$PY" probe_waitinit_envelope.py > results/waitinit-envelope.log
"$PY" check_vendor_service_symbols.py > results/recovered-symbols.log
"$PY" - <<'PY'
import json
from pathlib import Path
root=Path('.')
def get(name):return json.loads((root/name).read_text())
f=get('type-txt-original-arm-proof.json')
assert len(f['results'])==2 and all(x['returned'] for x in f['results'])
s=get('scene-after-type-fallback.json')
assert s['scene_initialization']['boundary']['symbol']=='fs_mpl_Create'
p=get('scene-after-synthetic-pool-config.json')
assert p['scene_initialization']['boundary']['symbol']=='sysDisMngInit'
assert not p['synthetic_pool_config_experiment']['pool_created_for_real']
t=get('original-task10-wait-boundary.json')
assert t['task39_initialization']['boundary']['symbol']=='pthread_self'
assert t['original_task10_waitinit_probe']['original_sysc_binding_entered']
w=get('waitinit-original-envelope.json')
assert w['envelope']['envelope']==[0,5,39,10] and not w['queue_send_performed']
v=get('vendor-service-availability.json')
assert v['scanned']==59
defined={(m['symbol']) for x in v['files'] for m in x['matches'] if m['defined']}
assert 'rq_tsk_WaitInit' in defined
assert not {'rq_fls_Open','fs_mpl_Create'}&defined
print("PASS 6 evidence reports, 59 recovered-file service symbol checks")
print("AUTHENTIC STARTUP / MENU RENDERED: NO")
PY
sha256sum *.py > results/script-sha256.txt
echo "PASS isolated original ARM file fallback, guarded scene and task10 wait boundaries"
