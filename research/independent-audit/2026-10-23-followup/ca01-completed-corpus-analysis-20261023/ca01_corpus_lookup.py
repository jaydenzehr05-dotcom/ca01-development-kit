import sqlite3,sys,json
from pathlib import Path
ROOT=Path('/home/starlight/projects/rav4-radio/system-audit/ca01-local-ai-supervisor-20261023')
c=sqlite3.connect('file:'+str(ROOT/'function_coverage.sqlite3')+'?mode=ro&immutable=1',uri=True);c.row_factory=sqlite3.Row
cache={}
def body(prefix,address):
 address=format(int(address,16),'x')
 row=c.execute('SELECT f.*,s.source_file,s.binary_name FROM functions f JOIN sources s USING(sha256) WHERE f.sha256 LIKE ? AND f.address=?',(prefix+'%',address)).fetchone()
 if row is None:return None
 path=row['source_file']
 if path not in cache:cache[path]=Path(path).read_text()
 print('\nSOURCE',row['binary_name'],row['sha256'],row['address'],row['name'],path)
 return cache[path][row['body_start']:row['body_end']] if row['body_start'] is not None else 'NO INDEXED BODY'
if __name__=='__main__':
 print(body(sys.argv[1],sys.argv[2]))
