"""OMOR EARNING License Bot + API (single-file server).

Dependencies: fastapi, uvicorn[standard], requests, pydantic, python-dotenv
Install: pip install fastapi "uvicorn[standard]" requests pydantic python-dotenv
Run: python OMOR_EARNING_bot.py

Set TELEGRAM_BOT_TOKEN in the server environment (or a private .env file).
Do not embed the bot token here or in the Chrome Extension. Any token shared in
chat should be revoked in BotFather and replaced with a fresh token.
"""
from pathlib import Path
from dotenv import load_dotenv
load_dotenv(Path(__file__).resolve().parent / ".env")

import os, re, sqlite3, secrets, string, threading, time, hashlib, hmac, base64, json
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
from fastapi import FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import requests

DB_PATH = os.getenv('LICENSE_DB', 'licenses.sqlite3')
BOT_TOKEN = os.getenv('TELEGRAM_BOT_TOKEN', '').strip()
ADMIN_USERNAME = os.getenv('ADMIN_TELEGRAM_USERNAME', 'Omor_Faruk789').lstrip('@').lower()
BOT_API = f'https://api.telegram.org/bot{BOT_TOKEN}' if BOT_TOKEN else ''
app = FastAPI(title='OMOR EARNING License API', version='1.0.0')
app.add_middleware(CORSMiddleware, allow_origins=['*'], allow_methods=['GET','POST'], allow_headers=['*'])

class RequestIn(BaseModel):
    telegram_username: str = Field(min_length=3, max_length=32)

class VerifyIn(BaseModel):
    token: str

class ActivateIn(BaseModel):
    license_key: str = Field(min_length=10, max_length=100)
    device_id: str = Field(min_length=16, max_length=128)

def db():
    c=sqlite3.connect(DB_PATH, timeout=20); c.row_factory=sqlite3.Row; return c

def init_db():
    with db() as c:
        c.executescript('''CREATE TABLE IF NOT EXISTS requests(
          request_id TEXT PRIMARY KEY, telegram_username TEXT NOT NULL, telegram_user_id INTEGER,
          verify_token TEXT UNIQUE, status TEXT NOT NULL, created_at TEXT NOT NULL,
          license_key TEXT UNIQUE, notified INTEGER NOT NULL DEFAULT 0);
          CREATE TABLE IF NOT EXISTS config(key TEXT PRIMARY KEY,value TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS licenses(license_key TEXT PRIMARY KEY, telegram_user_id INTEGER NOT NULL, request_id TEXT UNIQUE, created_at TEXT NOT NULL, device_id TEXT);''')
        cols=[r['name'] for r in c.execute('PRAGMA table_info(licenses)').fetchall()]
        if 'device_id' not in cols: c.execute('ALTER TABLE licenses ADD COLUMN device_id TEXT')

def api(method, payload=None, timeout=35):
    if not BOT_API: raise RuntimeError('TELEGRAM_BOT_TOKEN is not configured')
    r=requests.post(f'{BOT_API}/{method}', json=payload or {}, timeout=timeout); r.raise_for_status(); data=r.json()
    if not data.get('ok'): raise RuntimeError(data.get('description','Telegram API error'))
    return data['result']

def cfg(key):
    with db() as c:
        row=c.execute('SELECT value FROM config WHERE key=?',(key,)).fetchone()
        return row['value'] if row else None

def set_cfg(key,value):
    with db() as c: c.execute('INSERT INTO config(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value',(key,str(value)))

def extension_key_hash(value: str) -> str:
    return hashlib.sha256(value.encode('utf-8')).hexdigest()

def require_extension_key(value: str):
    expected = cfg('extension_key_hash')
    if not expected:
        raise HTTPException(503, 'Admin Bot থেকে /connect দিয়ে Extension Connection Code তৈরি করুন')
    actual = extension_key_hash((value or '').strip())
    if not hmac.compare_digest(expected, actual):
        raise HTTPException(401, 'Extension Connection Code সঠিক নয়')

def make_connection_code(public_url: str) -> str:
    public_url = public_url.strip().rstrip('/')
    if not re.fullmatch(r'https://[A-Za-z0-9.-]+(?::\d+)?', public_url):
        raise ValueError('HTTPS Render URL দিন, যেমন https://your-service.onrender.com')
    secret = cfg('extension_key')
    if not secret:
        secret = secrets.token_urlsafe(32)
        set_cfg('extension_key', secret)
    set_cfg('extension_key_hash', extension_key_hash(secret))
    payload = json.dumps({'v': 1, 'url': public_url, 'key': secret}, separators=(',', ':')).encode()
    return base64.urlsafe_b64encode(payload).decode().rstrip('=')

def send_admin_notice(req):
    admin_id=cfg('admin_telegram_id')
    if not admin_id: return False
    with db() as c:
        cur=c.execute('UPDATE requests SET notified=1 WHERE request_id=? AND notified=0',(req['request_id'],))
        if cur.rowcount != 1: return False
    text=(f"🆕 নতুন Lifetime License Request\n\n"
          f"👤 Telegram Username: @{req['telegram_username']}\n"
          f"🆔 Numeric User ID: {req['telegram_user_id']}\n"
          f"🔖 Request ID: {req['request_id']}\n"
          f"🕒 Date & Time: {req['created_at']}\n"
          f"📌 Status: {req['status']}")
    api('sendMessage', {'chat_id':int(admin_id),'text':text,'reply_markup':{'inline_keyboard':[[
      {'text':'✅ Approve','callback_data':'approve:'+req['request_id']},
      {'text':'❌ Reject','callback_data':'reject:'+req['request_id']}]]}})
    return True

def handle_update(u):
    msg=u.get('message') or {}
    if msg:
        chat=msg.get('chat',{}); sender=msg.get('from',{}); txt=msg.get('text','')
        if chat.get('type')=='private' and txt.startswith('/start'):
            parts=txt.split(maxsplit=1); payload=parts[1] if len(parts)>1 else ''
            username=(sender.get('username') or '').lower()
            if username==ADMIN_USERNAME:
                expected_id=os.getenv('ADMIN_TELEGRAM_ID','').strip()
                if expected_id and str(sender.get('id'))!=expected_id:
                    api('sendMessage',{'chat_id':sender['id'],'text':'❌ এই Telegram account অনুমোদিত Admin ID নয়।'})
                    return
                saved_admin=cfg('admin_telegram_id')
                if saved_admin and str(saved_admin)!=str(sender['id']):
                    api('sendMessage',{'chat_id':sender['id'],'text':'❌ Admin ID ইতিমধ্যে লক করা আছে। Backend operator-এর সহায়তা নিন।'}); return
                set_cfg('admin_telegram_id', sender['id'])
                api('sendMessage',{'chat_id':sender['id'],'text':'✅ Admin পরিচয় যাচাই হয়েছে। Approve/Reject বাটন ব্যবহার করুন। Connection Code: /connect https://আপনার-service.onrender.com\nBan/Unban: /ban USER_ID অথবা /unban USER_ID'})
            elif payload.startswith('verify_'):
                token=payload[7:]
                with db() as c:
                    row=c.execute('SELECT * FROM requests WHERE verify_token=?',(token,)).fetchone()
                    if not row:
                        api('sendMessage',{'chat_id':sender['id'],'text':'❌ Verification link সঠিক নয় বা মেয়াদ শেষ। Extension থেকে নতুন Request দিন।'}); return
                    if row['telegram_username'].lower()!=username:
                        api('sendMessage',{'chat_id':sender['id'],'text':f"❌ Username মিলেনি। Extension-এ @{row['telegram_username']} দিয়েছিলেন। একই Telegram account দিয়ে চেষ্টা করুন।"}); return
                    c.execute("UPDATE requests SET telegram_user_id=?, status='Pending', verify_token=NULL WHERE request_id=?",(sender['id'],row['request_id']))
                    fresh=c.execute('SELECT * FROM requests WHERE request_id=?',(row['request_id'],)).fetchone()
                api('sendMessage',{'chat_id':sender['id'],'text':'✅ Telegram account verified. আপনার License Request Admin-এর কাছে পাঠানো হয়েছে।'})
                if not fresh['notified']:
                    try: send_admin_notice(fresh)
                    except Exception as e:
                        with db() as c: c.execute('UPDATE requests SET notified=0 WHERE request_id=?',(fresh['request_id'],))
                        print('Admin notification failed:',e)
            else:
                api('sendMessage',{'chat_id':sender['id'],'text':'স্বাগতম। License Request verify করতে Extension থেকে পাওয়া verification link ব্যবহার করুন।'})
        admin_id=cfg('admin_telegram_id')
        if chat.get('type')=='private' and admin_id and str(sender.get('id'))==str(admin_id):
            parts=txt.strip().split()
            if parts and parts[0] == '/connect':
                public_url = parts[1] if len(parts) > 1 else (os.getenv('PUBLIC_BASE_URL') or os.getenv('RENDER_EXTERNAL_URL') or '')
                if not public_url:
                    api('sendMessage', {'chat_id': sender['id'], 'text': 'প্রথমে Render-এর Environment Variables-এ PUBLIC_BASE_URL=https://আপনার-service.onrender.com দিন। তারপর /connect লিখুন। চাইলে /connect https://আপনার-service.onrender.com লিখতে পারেন।'})
                else:
                    try:
                        code = make_connection_code(public_url)
                        msg = ('🔗 Extension Connection Code তৈরি হয়েছে.\n\n'
                               'এই কোডটি Extension-এর Connection Code ঘরে বসান.\n\n' + code + '\n\n'
                               'নোট: এটি Bot Token নয়। কোডটি Extension-এর shared connector key; এটি Admin ক্ষমতা দেয় না। এই কোডটি একই Backend-এর জন্য ব্যবহারযোগ্য থাকবে।')
                        api('sendMessage', {'chat_id': sender['id'], 'text': msg})
                    except Exception as e:
                        api('sendMessage', {'chat_id': sender['id'], 'text': '❌ Connection Code তৈরি হয়নি: ' + str(e)})
                return
            if len(parts)==2 and parts[0] in ('/ban','/unban') and parts[1].isdigit():
                uid=int(parts[1])
                with db() as c:
                    if parts[0]=='/ban': c.execute("UPDATE requests SET status='Banned' WHERE telegram_user_id=? AND status='Approved'",(uid,)); answer='⛔ User banned.'
                    else: c.execute("UPDATE requests SET status='Approved' WHERE telegram_user_id=? AND status='Banned'",(uid,)); answer='✅ User unbanned.'
                api('sendMessage',{'chat_id':sender['id'],'text':answer})
    q=u.get('callback_query')
    if q:
        data=q.get('data',''); sender=q.get('from',{}); admin_id=cfg('admin_telegram_id')
        if not admin_id or str(sender.get('id'))!=str(admin_id):
            api('answerCallbackQuery',{'callback_query_id':q['id'],'text':'অনুমতি নেই','show_alert':True}); return
        try: action,rid=data.split(':',1)
        except ValueError: return
        with db() as c:
            row=c.execute('SELECT * FROM requests WHERE request_id=?',(rid,)).fetchone()
            if not row: api('answerCallbackQuery',{'callback_query_id':q['id'],'text':'Request পাওয়া যায়নি'}); return
            if row['status']!='Pending':
                api('answerCallbackQuery',{'callback_query_id':q['id'],'text':'এই Request ইতিমধ্যে প্রসেস করা হয়েছে'}); return
            if action=='approve':
                key='OMOR-LIFE-' + ''.join(secrets.choice(string.ascii_uppercase+string.digits) for _ in range(24))
                c.execute("UPDATE requests SET status='Approved',license_key=? WHERE request_id=?",(key,rid))
                c.execute('INSERT INTO licenses(license_key,telegram_user_id,request_id,created_at) VALUES(?,?,?,?)',(key,row['telegram_user_id'],rid,datetime.now(timezone.utc).isoformat()))
            elif action=='reject':
                key=None; c.execute("UPDATE requests SET status='Rejected' WHERE request_id=?",(rid,))
            else: return
        if action=='approve':
            try: api('sendMessage',{'chat_id':row['telegram_user_id'],'text':f'🎉 আপনার Lifetime License অনুমোদিত হয়েছে!\n\n🔑 License Key:\n`{key}`','parse_mode':'Markdown'})
            except Exception as e: print('User delivery failed:',e)
            result=f'✅ Approved\nRequest: {rid}\nLicense: {key}'
        else:
            try: api('sendMessage',{'chat_id':row['telegram_user_id'],'text':f'❌ আপনার License Request প্রত্যাখ্যান করা হয়েছে।\nRequest ID: {rid}'})
            except Exception as e: print('User delivery failed:',e)
            result=f'❌ Rejected\nRequest: {rid}'
        api('editMessageText',{'chat_id':q['message']['chat']['id'],'message_id':q['message']['message_id'],'text':q['message'].get('text','')+'\n\n'+result})
        api('answerCallbackQuery',{'callback_query_id':q['id'],'text':'সফলভাবে আপডেট হয়েছে'})

def poll_bot():
    if not BOT_TOKEN: print('Telegram bot disabled: set TELEGRAM_BOT_TOKEN'); return
    try:
        api('deleteWebhook', {'drop_pending_updates': False})
    except Exception as e:
        print('Could not clear Telegram webhook before polling:', e)
    offset=None
    while True:
        try:
            updates=api('getUpdates',{'timeout':25,'offset':offset,'allowed_updates':['message','callback_query']},timeout=35)
            for u in updates:
                offset=u['update_id']+1
                try: handle_update(u)
                except Exception as e: print('Update handling error:',e)
        except Exception as e: print('Telegram polling error:',e); time.sleep(3)

@app.post('/license/activate')
def activate_license(data: ActivateIn, x_extension_key: str = Header(default='')):
    require_extension_key(x_extension_key)
    key=data.license_key.strip().upper(); device=data.device_id.strip()
    with db() as c:
        row=c.execute("SELECT l.license_key,l.device_id,r.status FROM licenses l JOIN requests r ON r.request_id=l.request_id WHERE l.license_key=?",(key,)).fetchone()
        if not row: raise HTTPException(404,'License Key সঠিক নয়')
        if row['status']!='Approved': raise HTTPException(403,'এই License সক্রিয় নয় বা বাতিল করা হয়েছে')
        if row['device_id'] and row['device_id']!=device: raise HTTPException(409,'এই License অন্য একটি ডিভাইসে যুক্ত আছে')
        c.execute('UPDATE licenses SET device_id=? WHERE license_key=?',(device,key))
    return {'ok':True,'active':True,'message':'Lifetime License সক্রিয় হয়েছে'}

@app.post('/license/validate')
def validate_license(data: ActivateIn, x_extension_key: str = Header(default='')):
    require_extension_key(x_extension_key)
    key=data.license_key.strip().upper(); device=data.device_id.strip()
    with db() as c:
        row=c.execute("SELECT l.device_id,r.status FROM licenses l JOIN requests r ON r.request_id=l.request_id WHERE l.license_key=?",(key,)).fetchone()
    if not row or row['status']!='Approved' or row['device_id']!=device:
        return {'ok':True,'active':False,'message':'License inactive, revoked, or device mismatch'}
    return {'ok':True,'active':True,'message':'Lifetime License valid'}

@app.on_event('startup')
def startup():
    init_db()
    if BOT_TOKEN:
        try:
            me = api('getMe')
            if me.get('username'):
                os.environ['TELEGRAM_BOT_USERNAME'] = me['username']
        except Exception as e:
            print('Telegram getMe failed:', e)
        threading.Thread(target=poll_bot,daemon=True).start()

@app.get('/license/ping')
def license_ping(x_extension_key: str = Header(default='')):
    require_extension_key(x_extension_key)
    return {'ok': True, 'connected': True, 'service': 'OMOR EARNING License API'}

@app.get('/health')
def health(): return {'ok':True,'telegram_configured':bool(BOT_TOKEN),'admin_verified':bool(cfg('admin_telegram_id'))}

@app.post('/license/request')
def create_request(data:RequestIn, x_extension_key: str = Header(default='')):
    require_extension_key(x_extension_key)
    if not BOT_TOKEN: raise HTTPException(503,'Backend admin bot is not configured')
    username=data.telegram_username.strip().lstrip('@')
    if not re.fullmatch(r'[A-Za-z0-9_]{5,32}',username): raise HTTPException(400,'সঠিক Telegram username দিন')
    rid='OMR-'+secrets.token_hex(5).upper(); token=secrets.token_urlsafe(24)
    created=datetime.now(ZoneInfo('Asia/Dhaka')).strftime('%Y-%m-%d %H:%M:%S (%Z)')
    with db() as c: c.execute("INSERT INTO requests(request_id,telegram_username,verify_token,status,created_at) VALUES(?,?,?,'Awaiting verification',?)",(rid,username,token,created))
    return {'ok':True,'request_id':rid,'status':'Awaiting verification','verification_url':f'https://t.me/{os.getenv("TELEGRAM_BOT_USERNAME","")}?start=verify_{token}','message':'Telegram bot-এ Start চাপ দিয়ে account verify করুন।'}

@app.get('/license/status/{request_id}')
def request_status(request_id:str):
    with db() as c: row=c.execute('SELECT request_id,status,license_key,created_at FROM requests WHERE request_id=?',(request_id,)).fetchone()
    if not row: raise HTTPException(404,'Request পাওয়া যায়নি')
    return dict(row)



if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", "8000")), reload=False)
