"""
AdsAnalytics Pro — Backend
Multi-platform OAuth: Facebook (thật) | Google + TikTok (placeholder)

.env:
  FB_APP_ID, FB_APP_SECRET
  GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET   (khi có)
  TIKTOK_APP_ID, TIKTOK_APP_SECRET         (khi có)
  APP_BASE_URL=http://localhost:5000
  SECRET_KEY=your-secret
"""
from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from functools import wraps
import sqlite3, hashlib, os, json, secrets
from datetime import datetime, timedelta
import random, urllib.request, urllib.parse
from dotenv import load_dotenv
load_dotenv()

FB_APP_ID            = os.getenv("FB_APP_ID","")
FB_APP_SECRET        = os.getenv("FB_APP_SECRET","")
GOOGLE_CLIENT_ID     = os.getenv("GOOGLE_CLIENT_ID","")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET","")
TIKTOK_APP_ID        = os.getenv("TIKTOK_APP_ID","")
TIKTOK_APP_SECRET    = os.getenv("TIKTOK_APP_SECRET","")
APP_BASE_URL         = os.getenv("APP_BASE_URL","http://localhost:5000")

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY","ads-dashboard-secret-2024")
DB = "instance/dashboard.db"

# ── DB ────────────────────────────────────────────────────────────────────────
def get_db():
    c = sqlite3.connect(DB); c.row_factory = sqlite3.Row; return c

def init_db():
    os.makedirs("instance", exist_ok=True)
    conn = get_db(); c = conn.cursor()
    c.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL, email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL, role TEXT DEFAULT 'user',
            is_active INTEGER DEFAULT 1, created_at TEXT DEFAULT (datetime('now')), last_login TEXT
        );
        CREATE TABLE IF NOT EXISTS platform_connections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL, platform TEXT NOT NULL,
            access_token TEXT, refresh_token TEXT, expires_at TEXT,
            account_id TEXT, account_name TEXT, scopes TEXT,
            is_active INTEGER DEFAULT 1,
            connected_at TEXT DEFAULT (datetime('now')), last_synced TEXT,
            UNIQUE(user_id, platform),
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS activity_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER, action TEXT, detail TEXT, ip TEXT,
            created_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS budgets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER, platform TEXT, monthly_limit REAL, month TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
    """)
    def hp(pw): return hashlib.sha256(pw.encode()).hexdigest()
    for u in [("admin","admin@ads.com",hp("admin123"),"admin"),
               ("nguyen_van_a","vana@company.com",hp("user123"),"user"),
               ("tran_thi_b","thib@agency.com",hp("user123"),"user"),
               ("le_van_c","vanc@shop.com",hp("user123"),"user")]:
        try: c.execute("INSERT INTO users (username,email,password,role) VALUES (?,?,?,?)",u)
        except: pass
    month = datetime.now().strftime("%Y-%m")
    for b in [(2,"facebook",50_000_000,month),(2,"google",50_000_000,month),(2,"tiktok",17_000_000,month),
               (3,"facebook",30_000_000,month),(3,"google",20_000_000,month)]:
        try: c.execute("INSERT INTO budgets (user_id,platform,monthly_limit,month) VALUES (?,?,?,?)",b)
        except: pass
    conn.commit(); conn.close()

# ── HELPERS ───────────────────────────────────────────────────────────────────
def hash_pw(pw): return hashlib.sha256(pw.encode()).hexdigest()

def log_activity(user_id, action, detail=""):
    conn = get_db()
    conn.execute("INSERT INTO activity_logs (user_id,action,detail,ip) VALUES (?,?,?,?)",
                 (user_id,action,detail,request.remote_addr))
    conn.commit(); conn.close()

def http_get(url, timeout=10):
    with urllib.request.urlopen(url,timeout=timeout) as r: return json.loads(r.read().decode())

def http_post(url, data, timeout=10):
    p = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(url,data=p,method="POST")
    req.add_header("Content-Type","application/x-www-form-urlencoded")
    with urllib.request.urlopen(req,timeout=timeout) as r: return json.loads(r.read().decode())

def login_required(f):
    @wraps(f)
    def d(*a,**kw):
        if "user_id" not in session: return redirect(url_for("login_page"))
        return f(*a,**kw)
    return d

def admin_required(f):
    @wraps(f)
    def d(*a,**kw):
        if "user_id" not in session: return redirect(url_for("login_page"))
        if session.get("role")!="admin": return jsonify({"error":"Forbidden"}),403
        return f(*a,**kw)
    return d

# ── PLATFORM CONNECTION HELPERS ───────────────────────────────────────────────
def get_connections(user_id):
    conn = get_db()
    rows = conn.execute("SELECT * FROM platform_connections WHERE user_id=? AND is_active=1",(user_id,)).fetchall()
    conn.close()
    return {r["platform"]:dict(r) for r in rows}

def save_connection(uid,platform,access_token,refresh_token,expires_at,account_id,account_name,scopes="[]"):
    conn = get_db()
    conn.execute("""
        INSERT INTO platform_connections (user_id,platform,access_token,refresh_token,expires_at,account_id,account_name,scopes,is_active,connected_at)
        VALUES (?,?,?,?,?,?,?,?,1,datetime('now'))
        ON CONFLICT(user_id,platform) DO UPDATE SET
        access_token=excluded.access_token, refresh_token=excluded.refresh_token,
        expires_at=excluded.expires_at, account_id=excluded.account_id,
        account_name=excluded.account_name, scopes=excluded.scopes,
        is_active=1, connected_at=datetime('now')
    """,(uid,platform,access_token,refresh_token,expires_at,account_id,account_name,scopes))
    conn.commit(); conn.close()

def disconnect_platform(uid,platform):
    conn = get_db()
    conn.execute("UPDATE platform_connections SET is_active=0 WHERE user_id=? AND platform=?",(uid,platform))
    conn.commit(); conn.close()

def token_expired(row):
    if not row.get("expires_at"): return False
    try: return datetime.now()>datetime.fromisoformat(row["expires_at"])
    except: return False

def token_expiring(row,days=7):
    if not row.get("expires_at"): return False
    try: return datetime.now()>datetime.fromisoformat(row["expires_at"])-timedelta(days=days)
    except: return False

# ══════════════════════════════════════════════════════════════════════════════
# FACEBOOK
# ══════════════════════════════════════════════════════════════════════════════
FB_SCOPES   = "ads_read,ads_management,read_insights"
FB_AUTH_URL  = "https://www.facebook.com/v18.0/dialog/oauth"
FB_TOKEN_URL = "https://graph.facebook.com/v18.0/oauth/access_token"
FB_API       = "https://graph.facebook.com/v18.0"

def fb_to_long_lived(short_token):
    params = urllib.parse.urlencode({"grant_type":"fb_exchange_token","client_id":FB_APP_ID,
        "client_secret":FB_APP_SECRET,"fb_exchange_token":short_token})
    d = http_get(f"{FB_TOKEN_URL}?{params}")
    exp = (datetime.now()+timedelta(seconds=int(d.get("expires_in",5_184_000)))).isoformat()
    return d["access_token"], exp

def fb_refresh(uid, row):
    try:
        new_tok,new_exp = fb_to_long_lived(row["access_token"])
        save_connection(uid,"facebook",new_tok,None,new_exp,row["account_id"],row["account_name"],row.get("scopes","[]"))
        log_activity(uid,"FB_TOKEN_REFRESH","Auto-refresh OK")
        return new_tok
    except Exception as e:
        print(f"[FB Refresh] {e}")
        conn = get_db()
        conn.execute("UPDATE platform_connections SET is_active=0 WHERE user_id=? AND platform='facebook'",(uid,))
        conn.commit(); conn.close()
        log_activity(uid,"FB_TOKEN_EXPIRED","Token hết hạn, cần kết nối lại")
        return None

def get_valid_fb_token(uid, row):
    if token_expired(row): return fb_refresh(uid,row)
    if token_expiring(row,7):
        try: fb_refresh(uid,row)
        except: pass
    return row["access_token"]

def fb_fetch(uid, row, days=7):
    token = get_valid_fb_token(uid,row)
    if not token or not row.get("account_id"): return None
    date_end   = datetime.now().strftime("%Y-%m-%d")
    date_start = (datetime.now()-timedelta(days=days)).strftime("%Y-%m-%d")
    url=(f"{FB_API}/{row['account_id']}/insights"
         f"?fields=spend,impressions,clicks,actions,action_values"
         f"&time_range={{\"since\":\"{date_start}\",\"until\":\"{date_end}\"}}"
         f"&time_increment=1&access_token={token}")
    try:
        res = http_get(url)
        if "error" in res:
            code = res["error"].get("code")
            if code in (190,102): fb_refresh(uid,row)
            return None
        rows = res.get("data",[])
        if not rows: return None
        labels,spend_s=[],[]
        ts=tr=cl=imp=0
        for r in rows:
            labels.append(r.get("date_start","")[-5:].replace("-","/"))
            sp=float(r.get("spend",0))*23_000
            spend_s.append(round(sp/1_000_000,2)); ts+=sp
            cl+=int(r.get("clicks",0)); imp+=int(r.get("impressions",0))
            for av in r.get("action_values",[]):
                if av["action_type"]=="purchase": tr+=float(av["value"])*23_000
        roas=round(tr/ts,2) if ts else 0
        roi=round((tr-ts)/ts*100,1) if ts else 0
        return {"platform":"facebook","source":"api","labels":labels,"spend_series":spend_s,
                "total_spend":round(ts),"total_revenue":round(tr),"roas":roas,"roi":roi,
                "cpa":round(ts/cl) if cl else 0,"clicks":cl,"impressions":imp,
                "ctr":round(cl/max(imp,1)*100,2)}
    except Exception as e:
        print(f"[FB Fetch] {e}"); return None

# ══════════════════════════════════════════════════════════════════════════════
# GOOGLE (placeholder)
# ══════════════════════════════════════════════════════════════════════════════
GOOGLE_AUTH_URL  = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_SCOPES    = "https://www.googleapis.com/auth/adwords"

def google_refresh(uid, row):
    if not row.get("refresh_token"): return None
    try:
        d=http_post(GOOGLE_TOKEN_URL,{"client_id":GOOGLE_CLIENT_ID,"client_secret":GOOGLE_CLIENT_SECRET,
            "refresh_token":row["refresh_token"],"grant_type":"refresh_token"})
        exp=(datetime.now()+timedelta(seconds=d.get("expires_in",3600))).isoformat()
        save_connection(uid,"google",d["access_token"],row["refresh_token"],exp,row["account_id"],row["account_name"])
        return d["access_token"]
    except Exception as e:
        print(f"[Google Refresh] {e}"); return None

def google_fetch(uid, row, days=7):
    # TODO: implement Google Ads API khi có credentials
    return None

# ══════════════════════════════════════════════════════════════════════════════
# TIKTOK (placeholder)
# ══════════════════════════════════════════════════════════════════════════════
TIKTOK_AUTH_URL  = "https://business-api.tiktok.com/portal/auth"
TIKTOK_TOKEN_URL = "https://business-api.tiktok.com/open_api/v1.3/oauth2/access_token/"

def tiktok_refresh(uid, row):
    if not row.get("refresh_token"): return None
    try:
        d=http_post(TIKTOK_TOKEN_URL,{"app_id":TIKTOK_APP_ID,"secret":TIKTOK_APP_SECRET,
            "refresh_token":row["refresh_token"],"grant_type":"refresh_token"}).get("data",{})
        exp=(datetime.now()+timedelta(seconds=d.get("access_token_expire_in",7_776_000))).isoformat()
        save_connection(uid,"tiktok",d["access_token"],d.get("refresh_token",row["refresh_token"]),
                        exp,row["account_id"],row["account_name"])
        return d["access_token"]
    except Exception as e:
        print(f"[TikTok Refresh] {e}"); return None

def tiktok_fetch(uid, row, days=7):
    # TODO: implement TikTok Ads API khi có credentials
    return None

# ══════════════════════════════════════════════════════════════════════════════
# MOCK DATA
# ══════════════════════════════════════════════════════════════════════════════
_MOCK_CFG={"facebook":{"base":6_200_000,"roas":3.1},"google":{"base":4_500_000,"roas":4.2},"tiktok":{"base":1_800_000,"roas":3.8}}

def mock_platform(uid, platform, days=7):
    cfg=_MOCK_CFG[platform]
    random.seed(uid*31+list(_MOCK_CFG).index(platform))
    labels,spend_s=[],[]
    for i in range(days):
        d=datetime.now()-timedelta(days=days-1-i)
        labels.append(d.strftime("%d/%m"))
        spend_s.append(round(cfg["base"]*random.uniform(0.7,1.3)/1_000_000,2))
    ts=sum(spend_s)*1_000_000; tr=ts*random.uniform(2.8,4.5)
    cl=random.randint(1_200,8_000); imp=random.randint(80_000,500_000)
    return {"platform":platform,"source":"mock","labels":labels,"spend_series":spend_s,
            "total_spend":round(ts),"total_revenue":round(tr),"roas":round(tr/ts,2),
            "roi":round((tr-ts)/ts*100,1),"cpa":round(ts/cl),"clicks":cl,"impressions":imp,
            "ctr":round(cl/imp*100,2)}

# ── FETCHERS MAP ──────────────────────────────────────────────────────────────
_FETCHERS={"facebook":fb_fetch,"google":google_fetch,"tiktok":tiktok_fetch}

def get_platform_data(uid, platform, days=7, force_mock=False):
    connections=get_connections(uid); row=connections.get(platform)
    if force_mock or not row:
        d=mock_platform(uid,platform,days)
        d["is_mock"]=True; d["is_connected"]=bool(row); d["needs_reauth"]=False; return d
    real=_FETCHERS[platform](uid,row,days)
    if real:
        real["is_mock"]=False; real["is_connected"]=True; real["needs_reauth"]=False
        conn=get_db()
        conn.execute("UPDATE platform_connections SET last_synced=? WHERE user_id=? AND platform=?",
                     (datetime.now().isoformat(),uid,platform))
        conn.commit(); conn.close(); return real
    d=mock_platform(uid,platform,days)
    d["is_mock"]=True; d["is_connected"]=True; d["needs_reauth"]=token_expired(row); return d

def get_all_data(uid, days=7, force_mock=False):
    platforms={p:get_platform_data(uid,p,days,force_mock) for p in ["facebook","google","tiktok"]}
    ts=sum(p["total_spend"] for p in platforms.values())
    tr=sum(p["total_revenue"] for p in platforms.values())
    cl=sum(p["clicks"] for p in platforms.values())
    labels=platforms["facebook"]["labels"]
    merged=[round(sum(platforms[p]["spend_series"][i] for p in platforms),2) for i in range(len(labels))]
    connected=get_connections(uid)
    return {"source":"mixed" if any(not p["is_mock"] for p in platforms.values()) else "mock",
            "labels":labels,"merged_series":merged,"total_spend":round(ts),"total_revenue":round(tr),
            "roas":round(tr/ts,2) if ts else 0,"roi":round((tr-ts)/ts*100,1) if ts else 0,
            "cpa":round(ts/cl) if cl else 0,"platforms":platforms,"connected_count":len(connected)}

# ══════════════════════════════════════════════════════════════════════════════
# PAGES
# ══════════════════════════════════════════════════════════════════════════════
@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("admin_page") if session.get("role")=="admin" else url_for("dashboard_page"))
    return redirect(url_for("login_page"))

@app.route("/login")
def login_page():
    if "user_id" in session: return redirect(url_for("index"))
    return render_template("login.html")

@app.route("/dashboard")
@login_required
def dashboard_page():
    return render_template("dashboard.html",username=session["username"],role=session["role"])

@app.route("/admin")
@login_required
def admin_page():
    if session.get("role")!="admin": return redirect(url_for("dashboard_page"))
    return render_template("admin.html",username=session["username"])

# ── API AUTH ──────────────────────────────────────────────────────────────────
@app.route("/api/login",methods=["POST"])
def api_login():
    data=request.json
    conn=get_db()
    user=conn.execute("SELECT * FROM users WHERE username=? AND password=? AND is_active=1",
                      (data["username"],hash_pw(data["password"]))).fetchone()
    conn.close()
    if not user: return jsonify({"error":"Sai tài khoản hoặc mật khẩu"}),401
    session.update({"user_id":user["id"],"username":user["username"],"role":user["role"]})
    db=get_db(); db.execute("UPDATE users SET last_login=? WHERE id=?",(datetime.now().isoformat(),user["id"]))
    db.commit(); db.close()
    log_activity(user["id"],"LOGIN","Đăng nhập thành công")
    return jsonify({"role":user["role"],"username":user["username"]})

@app.route("/api/logout",methods=["POST"])
@login_required
def api_logout():
    log_activity(session["user_id"],"LOGOUT","Đăng xuất")
    session.clear(); return jsonify({"ok":True})

# ── API CONNECTIONS ───────────────────────────────────────────────────────────
@app.route("/api/connections")
@login_required
def api_connections():
    connections=get_connections(session["user_id"])
    can_connect={"facebook":bool(FB_APP_ID and FB_APP_SECRET),
                 "google":bool(GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET),
                 "tiktok":bool(TIKTOK_APP_ID and TIKTOK_APP_SECRET)}
    result={}
    for p in ["facebook","google","tiktok"]:
        if p in connections:
            row=connections[p]; days_left=None; exp_str=None
            if row.get("expires_at"):
                try:
                    exp_dt=datetime.fromisoformat(row["expires_at"])
                    days_left=max(0,(exp_dt-datetime.now()).days); exp_str=exp_dt.strftime("%d/%m/%Y")
                except: pass
            result[p]={"connected":True,"can_connect":can_connect[p],"account_name":row.get("account_name",""),
                       "account_id":row.get("account_id",""),"expires":exp_str,"days_left":days_left,
                       "needs_reauth":token_expired(row),"last_synced":row.get("last_synced")}
        else:
            result[p]={"connected":False,"can_connect":can_connect[p]}
    return jsonify(result)

@app.route("/api/disconnect/<platform>",methods=["POST"])
@login_required
def api_disconnect(platform):
    if platform not in ("facebook","google","tiktok"): return jsonify({"error":"Invalid platform"}),400
    disconnect_platform(session["user_id"],platform)
    log_activity(session["user_id"],"DISCONNECT_PLATFORM",f"Ngắt kết nối {platform}")
    return jsonify({"ok":True})

# ── API DASHBOARD DATA ────────────────────────────────────────────────────────
@app.route("/api/dashboard/<platform>")
@login_required
def api_dashboard_platform(platform):
    if platform not in ("facebook","google","tiktok","all"): return jsonify({"error":"Invalid platform"}),400
    days=int(request.args.get("days",7))
    force_mock=request.args.get("force_mock","0")=="1"
    uid=session["user_id"]
    data=get_all_data(uid,days,force_mock) if platform=="all" else get_platform_data(uid,platform,days,force_mock)
    conn=get_db()
    budgets=conn.execute("SELECT platform,monthly_limit FROM budgets WHERE user_id=?",(uid,)).fetchall()
    conn.close()
    data["budgets"]={b["platform"]:b["monthly_limit"] for b in budgets}
    log_activity(uid,"VIEW_DASHBOARD",f"tab={platform} days={days} mock={force_mock}")
    return jsonify(data)

# ── FACEBOOK OAUTH ────────────────────────────────────────────────────────────
@app.route("/auth/facebook")
@login_required
def auth_facebook():
    if not FB_APP_ID: return jsonify({"error":"FB_APP_ID chưa cấu hình trong .env"}),503
    state=secrets.token_urlsafe(16); session["oauth_state_fb"]=state
    params=urllib.parse.urlencode({"client_id":FB_APP_ID,
        "redirect_uri":f"{APP_BASE_URL}/auth/facebook/callback",
        "scope":FB_SCOPES,"state":state,"response_type":"code"})
    return redirect(f"{FB_AUTH_URL}?{params}")

@app.route("/auth/facebook/callback")
@login_required
def auth_facebook_callback():
    if request.args.get("state")!=session.pop("oauth_state_fb",None):
        return redirect(url_for("dashboard_page")+"?error=invalid_state")
    error=request.args.get("error")
    if error: return redirect(url_for("dashboard_page")+f"?error={error}")
    code=request.args.get("code")
    if not code: return redirect(url_for("dashboard_page")+"?error=no_code")
    try:
        params=urllib.parse.urlencode({"client_id":FB_APP_ID,"client_secret":FB_APP_SECRET,
            "redirect_uri":f"{APP_BASE_URL}/auth/facebook/callback","code":code})
        short=http_get(f"{FB_TOKEN_URL}?{params}")["access_token"]
        long_tok,expires_at=fb_to_long_lived(short)
        me=http_get(f"{FB_API}/me?fields=id,name&access_token={long_tok}")
        accounts=http_get(f"{FB_API}/me/adaccounts?fields=id,name,account_status&access_token={long_tok}")
        ad_list=accounts.get("data",[])
        active=next((a for a in ad_list if a.get("account_status")==1),ad_list[0] if ad_list else None)
        account_id=active["id"] if active else ""
        account_name=active.get("name","") if active else me.get("name","")
        save_connection(session["user_id"],"facebook",long_tok,None,expires_at,
                        account_id,account_name,json.dumps(FB_SCOPES.split(",")))
        log_activity(session["user_id"],"CONNECT_PLATFORM",f"Facebook: {account_name} ({account_id})")
        return redirect(url_for("dashboard_page")+"?connected=facebook")
    except Exception as e:
        print(f"[FB Callback] {e}")
        return redirect(url_for("dashboard_page")+"?error=fb_oauth_failed")

# ── GOOGLE OAUTH (placeholder) ────────────────────────────────────────────────
@app.route("/auth/google")
@login_required
def auth_google():
    if not GOOGLE_CLIENT_ID:
        return jsonify({"error":"Chưa cấu hình","guide":"Tạo tại console.cloud.google.com → APIs & Services → OAuth 2.0 Client ID. Thêm GOOGLE_CLIENT_ID + GOOGLE_CLIENT_SECRET vào .env"}),503
    state=secrets.token_urlsafe(16); session["oauth_state_google"]=state
    params=urllib.parse.urlencode({"client_id":GOOGLE_CLIENT_ID,
        "redirect_uri":f"{APP_BASE_URL}/auth/google/callback",
        "scope":GOOGLE_SCOPES,"state":state,"response_type":"code",
        "access_type":"offline","prompt":"consent"})
    return redirect(f"{GOOGLE_AUTH_URL}?{params}")

@app.route("/auth/google/callback")
@login_required
def auth_google_callback():
    if request.args.get("state")!=session.pop("oauth_state_google",None):
        return redirect(url_for("dashboard_page")+"?error=invalid_state")
    code=request.args.get("code")
    if not code: return redirect(url_for("dashboard_page")+f"?error={request.args.get('error','no_code')}")
    try:
        d=http_post(GOOGLE_TOKEN_URL,{"code":code,"client_id":GOOGLE_CLIENT_ID,
            "client_secret":GOOGLE_CLIENT_SECRET,
            "redirect_uri":f"{APP_BASE_URL}/auth/google/callback","grant_type":"authorization_code"})
        exp=(datetime.now()+timedelta(seconds=d.get("expires_in",3600))).isoformat()
        save_connection(session["user_id"],"google",d["access_token"],d.get("refresh_token",""),
                        exp,"TODO_CUSTOMER_ID","Google Ads Account")
        log_activity(session["user_id"],"CONNECT_PLATFORM","Google Ads OK")
        return redirect(url_for("dashboard_page")+"?connected=google")
    except Exception as e:
        print(f"[Google Callback] {e}")
        return redirect(url_for("dashboard_page")+"?error=google_oauth_failed")

# ── TIKTOK OAUTH (placeholder) ────────────────────────────────────────────────
@app.route("/auth/tiktok")
@login_required
def auth_tiktok():
    if not TIKTOK_APP_ID:
        return jsonify({"error":"Chưa cấu hình","guide":"Tạo tại business.tiktok.com/portal/apps → Marketing API. Thêm TIKTOK_APP_ID + TIKTOK_APP_SECRET vào .env"}),503
    state=secrets.token_urlsafe(16); session["oauth_state_tiktok"]=state
    params=urllib.parse.urlencode({"app_id":TIKTOK_APP_ID,
        "redirect_uri":f"{APP_BASE_URL}/auth/tiktok/callback","state":state})
    return redirect(f"{TIKTOK_AUTH_URL}?{params}")

@app.route("/auth/tiktok/callback")
@login_required
def auth_tiktok_callback():
    if request.args.get("state")!=session.pop("oauth_state_tiktok",None):
        return redirect(url_for("dashboard_page")+"?error=invalid_state")
    code=request.args.get("auth_code") or request.args.get("code")
    if not code: return redirect(url_for("dashboard_page")+"?error=no_code")
    try:
        d=http_post(TIKTOK_TOKEN_URL,{"app_id":TIKTOK_APP_ID,"secret":TIKTOK_APP_SECRET,"auth_code":code}).get("data",{})
        exp=(datetime.now()+timedelta(seconds=d.get("access_token_expire_in",7_776_000))).isoformat()
        save_connection(session["user_id"],"tiktok",d["access_token"],d.get("refresh_token",""),
                        exp,str(d.get("advertiser_id","")),"TikTok Ads Account")
        log_activity(session["user_id"],"CONNECT_PLATFORM","TikTok Ads OK")
        return redirect(url_for("dashboard_page")+"?connected=tiktok")
    except Exception as e:
        print(f"[TikTok Callback] {e}")
        return redirect(url_for("dashboard_page")+"?error=tiktok_oauth_failed")

# ── API ADMIN ─────────────────────────────────────────────────────────────────
@app.route("/api/admin/users")
@admin_required
def api_admin_users():
    conn=get_db()
    users=conn.execute("SELECT id,username,email,role,is_active,created_at,last_login FROM users ORDER BY id").fetchall()
    result=[]
    for u in users:
        ud=dict(u)
        platforms=conn.execute("SELECT platform,account_name,is_active,last_synced FROM platform_connections WHERE user_id=?",(u["id"],)).fetchall()
        ud["platforms"]=[dict(p) for p in platforms]; result.append(ud)
    conn.close(); return jsonify(result)

@app.route("/api/admin/users/<int:uid>/toggle",methods=["POST"])
@admin_required
def api_toggle_user(uid):
    conn=get_db(); user=conn.execute("SELECT * FROM users WHERE id=?",(uid,)).fetchone()
    if not user: conn.close(); return jsonify({"error":"Not found"}),404
    new_status=0 if user["is_active"] else 1
    conn.execute("UPDATE users SET is_active=? WHERE id=?",(new_status,uid))
    conn.commit(); conn.close()
    log_activity(session["user_id"],"TOGGLE_USER",f'{"Mở khóa" if new_status else "Khóa"} user {user["username"]}')
    return jsonify({"is_active":new_status})

@app.route("/api/admin/users",methods=["POST"])
@admin_required
def api_create_user():
    data=request.json; conn=get_db()
    try:
        conn.execute("INSERT INTO users (username,email,password,role) VALUES (?,?,?,?)",
                     (data["username"],data["email"],hash_pw(data["password"]),data.get("role","user")))
        conn.commit()
        log_activity(session["user_id"],"CREATE_USER",f'Tạo user {data["username"]}')
        return jsonify({"ok":True})
    except sqlite3.IntegrityError: return jsonify({"error":"Username hoặc email đã tồn tại"}),400
    finally: conn.close()

@app.route("/api/admin/users/<int:uid>/role",methods=["POST"])
@admin_required
def api_change_role(uid):
    role=request.json.get("role")
    if role not in ("admin","user"): return jsonify({"error":"Invalid role"}),400
    conn=get_db(); conn.execute("UPDATE users SET role=? WHERE id=?",(role,uid)); conn.commit(); conn.close()
    log_activity(session["user_id"],"CHANGE_ROLE",f"Đổi role user #{uid} → {role}")
    return jsonify({"ok":True})

@app.route("/api/admin/logs")
@admin_required
def api_admin_logs():
    uid=request.args.get("user_id"); conn=get_db()
    if uid:
        logs=conn.execute("SELECT l.*,u.username FROM activity_logs l JOIN users u ON l.user_id=u.id WHERE l.user_id=? ORDER BY l.created_at DESC LIMIT 100",(uid,)).fetchall()
    else:
        logs=conn.execute("SELECT l.*,u.username FROM activity_logs l JOIN users u ON l.user_id=u.id ORDER BY l.created_at DESC LIMIT 200").fetchall()
    conn.close(); return jsonify([dict(l) for l in logs])

@app.route("/api/admin/stats")
@admin_required
def api_admin_stats():
    conn=get_db()
    total=conn.execute('SELECT COUNT(*) as c FROM users WHERE role="user"').fetchone()["c"]
    active=conn.execute('SELECT COUNT(*) as c FROM users WHERE role="user" AND is_active=1').fetchone()["c"]
    today=conn.execute('SELECT COUNT(*) as c FROM activity_logs WHERE action="LOGIN" AND date(created_at)=date("now")').fetchone()["c"]
    conns=conn.execute('SELECT COUNT(*) as c FROM platform_connections WHERE is_active=1').fetchone()["c"]
    conn.close()
    total_spend=sum(get_all_data(i,30,force_mock=True)["total_spend"] for i in range(2,5))
    return jsonify({"total_users":total,"active_users":active,"today_logins":today,
                    "total_connections":conns,"total_spend":total_spend})

@app.route("/api/admin/preview-dashboard")
@admin_required
def api_admin_preview_dashboard():
    uid=request.args.get("user_id",type=int); days=int(request.args.get("days",7))
    if not uid: return jsonify({"error":"Missing user_id"}),400
    data=get_all_data(uid,days,force_mock=True)
    conn=get_db()
    budgets=conn.execute("SELECT platform,monthly_limit FROM budgets WHERE user_id=?",(uid,)).fetchall()
    conn.close(); data["budgets"]={b["platform"]:b["monthly_limit"] for b in budgets}
    log_activity(session["user_id"],"VIEW_DASHBOARD",f"Admin preview user #{uid}")
    return jsonify(data)

def get_all_data_v2(uid, days=7, force_mock=False):
    platforms = {p: get_platform_data(uid, p, days, force_mock) for p in ["facebook", "google", "tiktok"]}
    ts = sum(p["total_spend"] for p in platforms.values())
    tr = sum(p["total_revenue"] for p in platforms.values())
    cl = sum(p["clicks"] for p in platforms.values())
    labels = platforms["facebook"]["labels"]
    merged = [round(sum(platforms[p]["spend_series"][i] for p in platforms), 2) for i in range(len(labels))]
    connected = get_connections(uid)
 
    # spend_series dạng dict để frontend dùng d.spend_series.facebook
    spend_series = {
        "facebook": platforms["facebook"]["spend_series"],
        "google":   platforms["google"]["spend_series"],
        "tiktok":   platforms["tiktok"]["spend_series"],
        "merged":   merged,
    }
 
    # channel_stats cho bảng hiệu suất
    channel_stats = {
        p: {
            "spend":       platforms[p]["total_spend"],
            "revenue":     platforms[p]["total_revenue"],
            "roas":        platforms[p]["roas"],
            "roi":         platforms[p]["roi"],
            "cpa":         platforms[p]["cpa"],
            "clicks":      platforms[p]["clicks"],
            "impressions": platforms[p]["impressions"],
            "ctr":         platforms[p]["ctr"],
            "is_mock":     platforms[p]["is_mock"],
            "is_connected":platforms[p]["is_connected"],
        }
        for p in ["facebook", "google", "tiktok"]
    }
 
    return {
        "source":        "mixed" if any(not p["is_mock"] for p in platforms.values()) else "mock",
        "labels":        labels,
        "spend_series":  spend_series,
        "total_spend":   round(ts),
        "total_revenue": round(tr),
        "roas":          round(tr / ts, 2) if ts else 0,
        "roi":           round((tr - ts) / ts * 100, 1) if ts else 0,
        "cpa":           round(ts / cl) if cl else 0,
        "channel_stats": channel_stats,
        "platforms":     platforms,
        "connected_count": len(connected),
    }
 
 
# ── ROUTE MỚI: /api/dashboard-data ──────────────────────────────────────────
# Thêm route này vào app.py (trước if __name__=="__main__":)
 
@app.route("/api/dashboard-data")
@login_required
def api_dashboard_data():
    """
    Route tổng hợp cho dashboard.html.
    Params:
      ?days=7|30|90
      ?platform=all|facebook|google|tiktok  (default: all)
      ?force_mock=0|1
    """
    days       = int(request.args.get("days", 7))
    platform   = request.args.get("platform", "all")
    force_mock = request.args.get("force_mock", "0") == "1"
    uid        = session["user_id"]
 
    conn = get_db()
    budgets_rows = conn.execute(
        "SELECT platform, monthly_limit FROM budgets WHERE user_id=?", (uid,)
    ).fetchall()
    conn.close()
    budgets = {b["platform"]: b["monthly_limit"] for b in budgets_rows}
 
    connections = get_connections(uid)
 
    if platform == "all":
        data = get_all_data_v2(uid, days, force_mock)
    else:
        if platform not in ("facebook", "google", "tiktok"):
            return jsonify({"error": "Invalid platform"}), 400
        pd = get_platform_data(uid, platform, days, force_mock)
        # Wrap thành format giống all nhưng chỉ 1 platform
        data = {
            "source":        "mock" if pd["is_mock"] else "api",
            "labels":        pd["labels"],
            "spend_series": {platform: pd["spend_series"]},
            "total_spend":   pd["total_spend"],
            "total_revenue": pd["total_revenue"],
            "roas":          pd["roas"],
            "roi":           pd["roi"],
            "cpa":           pd["cpa"],
            "channel_stats": {
                platform: {
                    "spend":       pd["total_spend"],
                    "revenue":     pd["total_revenue"],
                    "roas":        pd["roas"],
                    "roi":         pd["roi"],
                    "cpa":         pd["cpa"],
                    "clicks":      pd["clicks"],
                    "impressions": pd["impressions"],
                    "ctr":         pd["ctr"],
                    "is_mock":     pd["is_mock"],
                    "is_connected":pd["is_connected"],
                }
            },
            "connected_count": len(connections),
        }
 
    data["budgets"] = budgets
 
    # Flag cho frontend biết có cần show noAdsModal không
    # (chỉ show nếu KHÔNG có connection nào hết)
    data["no_ads_data"] = len(connections) == 0
 
    log_activity(uid, "VIEW_DASHBOARD", f"platform={platform} days={days} mock={force_mock}")
    return jsonify(data)
 
 
# ── ROUTE: /api/connections/status ──────────────────────────────────────────
# Trả về trạng thái kết nối nhanh cho sidebar Settings
@app.route("/api/connections/status")
@login_required
def api_connections_status():
    """Shortcut trả về connected platforms cho UI sidebar"""
    connections = get_connections(session["user_id"])
    can_connect = {
        "facebook": bool(FB_APP_ID and FB_APP_SECRET),
        "google":   bool(GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET),
        "tiktok":   bool(TIKTOK_APP_ID and TIKTOK_APP_SECRET),
    }
    result = {}
    for p in ["facebook", "google", "tiktok"]:
        if p in connections:
            row = connections[p]
            days_left = None
            if row.get("expires_at"):
                try:
                    exp_dt = datetime.fromisoformat(row["expires_at"])
                    days_left = max(0, (exp_dt - datetime.now()).days)
                except:
                    pass
            result[p] = {
                "connected":    True,
                "can_connect":  can_connect[p],
                "account_name": row.get("account_name", ""),
                "account_id":   row.get("account_id", ""),
                "days_left":    days_left,
                "needs_reauth": token_expired(row),
                "last_synced":  row.get("last_synced"),
            }
        else:
            result[p] = {"connected": False, "can_connect": can_connect[p]}
    return jsonify(result)

if __name__=="__main__":
    init_db(); app.run(debug=True,port=5000)