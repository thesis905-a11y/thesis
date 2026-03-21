# =====================================================================
# SEIZURE MONITOR BACKEND - v21
#
# FIXES vs v20:
#
# [FIX 1] Motion stops → seizure closes immediately (after grace).
#         "Wala nang galaw = wala nang seizure session na bukas."
#         Grace period: GTCS_BACKEND_GRACE_SECONDS = 3s.
#         When all devices go to seizure_flag=False AND the 7s window
#         expires → grace starts → after 3s → close.
#
# [FIX 2] Duration = actual motion time (motion_start → motion_stop).
#         NOT wall clock from session open to now.
#         motion_started = when GTCS first triggered (devices crossed
#         threshold). motion_stopped = when devices first went to 0.
#         duration = motion_stopped - motion_started.
#
# [FIX 3] SD card upload (upload_seizure_event) only supplements the
#         real-time PATH B detection — it does NOT override or restart
#         a session that PATH B already closed correctly.
#         Duplicate check: if a session with the same start_time
#         already exists (within ±30s), skip the SD upload.
#         If PATH B already wrote the correct session, SD upload is a
#         true duplicate and is skipped.
#
# [FIX 4] SEIZURE_WINDOW_SECONDS = 7s (matches ESP32 GTCS_STICKY_MS=2s
#         + upload interval ~1.2s × 3 devices = ~3.6s worst case stagger,
#         7s gives safe margin without being too long).
#
# [FIX 5] Removed _post_upload_suppress_until logic — it caused PATH B
#         to be suppressed for 30s after every SD upload, even when the
#         patient was still actively seizing. This was wrong.
#         Instead: rely on duplicate check in upload_seizure_event.
#
# [FIX 6] Grace period applies to the WHOLE user (not per-device):
#         once ALL devices show 0, grace starts. If ANY device comes
#         back True within grace → grace resets, GTCS continues.
#
# LOGIC SUMMARY (matches ESP32 v25):
#   - seizure_flag=True per-device while GTCS window detects motion
#   - Backend counts devices with True reading in last 7s
#   - count≥2 for 15s OR count≥1 for 20s → GTCS session opens
#   - When count→0: grace starts (3s)
#   - If count comes back before grace expires → grace resets
#   - After grace → session closes, duration = trigger→motion_stop
#
# =====================================================================

from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime, timedelta, timezone
from jose import JWTError, jwt
import databases
import sqlalchemy
from fastapi.security import OAuth2PasswordBearer
import os
import json
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import and_
from fastapi.responses import StreamingResponse
import csv
import io

PHT = timezone(timedelta(hours=8))

def to_pht(dt_utc: datetime) -> datetime:
    if dt_utc.tzinfo is None:
        dt_utc = dt_utc.replace(tzinfo=timezone.utc)
    return dt_utc.astimezone(PHT)

def ts_pht_iso(dt_utc: Optional[datetime]) -> Optional[str]:
    if dt_utc is None:
        return None
    if dt_utc.tzinfo is None:
        dt_utc = dt_utc.replace(tzinfo=timezone.utc)
    return dt_utc.astimezone(PHT).strftime("%Y-%m-%dT%H:%M:%S")

def parse_esp32_timestamp(timestamp_ms: int) -> datetime:
    ts_val = float(timestamp_ms)
    if ts_val > 1e12:
        ts_val = ts_val / 1000.0
    if 946684800 <= ts_val <= 4102444800:
        return datetime.fromtimestamp(ts_val, tz=timezone.utc)
    print(f"[WARNING] Invalid ESP32 timestamp: {timestamp_ms} — using server time")
    return datetime.now(timezone.utc)

def parse_unix_seconds(ts: int) -> datetime:
    if 946684800 <= ts <= 4102444800:
        return datetime.fromtimestamp(float(ts), tz=timezone.utc)
    print(f"[WARNING] Invalid unix timestamp: {ts} — using server time")
    return datetime.now(timezone.utc)

if "DATABASE_URL" in os.environ:
    raw_url = os.environ["DATABASE_URL"]
    if raw_url.startswith("postgres://"):
        raw_url = raw_url.replace("postgres://", "postgresql://", 1)
    DATABASE_URL = raw_url
else:
    DATABASE_URL = f"sqlite:///{os.path.abspath('seizure.db')}"

database = databases.Database(DATABASE_URL)
metadata = sqlalchemy.MetaData()
engine = sqlalchemy.create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
)

users = sqlalchemy.Table(
    "users", metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("username", sqlalchemy.String, unique=True),
    sqlalchemy.Column("password", sqlalchemy.String),
    sqlalchemy.Column("is_admin", sqlalchemy.Boolean, default=False),
)

devices = sqlalchemy.Table(
    "devices", metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("user_id", sqlalchemy.Integer, sqlalchemy.ForeignKey("users.id")),
    sqlalchemy.Column("device_id", sqlalchemy.String, unique=True),
    sqlalchemy.Column("label", sqlalchemy.String),
)

device_data = sqlalchemy.Table(
    "device_data", metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("device_id", sqlalchemy.String),
    sqlalchemy.Column("timestamp", sqlalchemy.DateTime(timezone=True)),
    sqlalchemy.Column("payload", sqlalchemy.Text),
)

sensor_data = sqlalchemy.Table(
    "sensor_data", metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("device_id", sqlalchemy.String, index=True),
    sqlalchemy.Column("timestamp", sqlalchemy.DateTime(timezone=True), index=True),
    sqlalchemy.Column("accel_x", sqlalchemy.Float),
    sqlalchemy.Column("accel_y", sqlalchemy.Float),
    sqlalchemy.Column("accel_z", sqlalchemy.Float),
    sqlalchemy.Column("gyro_x", sqlalchemy.Float),
    sqlalchemy.Column("gyro_y", sqlalchemy.Float),
    sqlalchemy.Column("gyro_z", sqlalchemy.Float),
    sqlalchemy.Column("battery_percent", sqlalchemy.Integer),
    sqlalchemy.Column("seizure_flag", sqlalchemy.Boolean, default=False),
)

device_seizure_sessions = sqlalchemy.Table(
    "device_seizure_sessions", metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("device_id", sqlalchemy.String, index=True),
    sqlalchemy.Column("start_time", sqlalchemy.DateTime(timezone=True)),
    sqlalchemy.Column("end_time", sqlalchemy.DateTime(timezone=True), nullable=True),
)

user_seizure_sessions = sqlalchemy.Table(
    "user_seizure_sessions", metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("user_id", sqlalchemy.Integer, sqlalchemy.ForeignKey("users.id")),
    sqlalchemy.Column("type", sqlalchemy.String),
    sqlalchemy.Column("start_time", sqlalchemy.DateTime(timezone=True)),
    sqlalchemy.Column("end_time", sqlalchemy.DateTime(timezone=True), nullable=True),
    sqlalchemy.Column("duration_seconds", sqlalchemy.Integer, nullable=True),
    sqlalchemy.Column("seizing_devices", sqlalchemy.Text, nullable=True),
)

metadata.create_all(engine)

SECRET_KEY = os.environ.get("SECRET_KEY", "CHANGE_THIS_SECRET")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/login")

CONNECTED_THRESHOLD_SECONDS     = 60
STALE_SESSION_THRESHOLD_SECONDS = 120
MIN_GTCS_DURATION_SECONDS       = 3

# =====================================================================
# JERK THRESHOLDS (must match ESP32)
# =====================================================================
JERK_FIXED_DURATION_SECONDS     = 5
JERK_TO_GTCS_ESCALATION_SECONDS = 10
JERK_REOPEN_SUPPRESS_SECONDS    = 5

# =====================================================================
# GTCS THRESHOLDS (must match ESP32)
# =====================================================================
GTCS_THRESHOLD_1_DEVICE_SECONDS     = 20
GTCS_THRESHOLD_MULTI_DEVICE_SECONDS = 15
RECENT_GTCS_SUPPRESS_JERK_SECONDS   = 60

# [FIX 6] Grace period: how long after ALL devices go to 0 before closing.
# Must be > upload interval (1.2s) to tolerate stagger.
# Set to 3s — if no device uploads True within 3s of last motion, close.
GTCS_BACKEND_GRACE_SECONDS = 3

# =====================================================================
# [FIX 4] TIME WINDOW — how long a seizure_flag=True reading "counts".
# 7s: upload interval ~1.2s × 3 devices = 3.6s worst case + margin.
# Matches ESP32 GTCS_STICKY_MS (2s) + upload delay.
# =====================================================================
SEIZURE_WINDOW_SECONDS = 7

# =====================================================================
# IN-MEMORY STATE
# These track per-user state between uploads.
# =====================================================================
# user_id → datetime when GTCS motion threshold was first crossed (trigger time)
_gtcs_motion_started: dict = {}

# user_id → datetime when ALL devices first went to 0 (motion lost time)
# Grace timer starts from here.
_gtcs_motion_lost_time: dict = {}

# user_id → datetime until new Jerk session is suppressed (post-close)
_jerk_suppress_until: dict = {}


# =====================================================================
# PYDANTIC MODELS
# =====================================================================
class UserCreate(BaseModel):
    username: str
    password: str
    is_admin: Optional[bool] = False

class Token(BaseModel):
    access_token: str
    token_type: str

class LoginRequest(BaseModel):
    username: str
    password: str

class DeviceRegister(BaseModel):
    device_id: str
    label: Optional[str] = None

class DeviceUpdate(BaseModel):
    label: str

class UnifiedESP32Payload(BaseModel):
    device_id: str
    timestamp_ms: int
    battery_percent: int
    seizure_flag: bool
    accel_x: float
    accel_y: float
    accel_z: float
    gyro_x: float
    gyro_y: float
    gyro_z: float

class SeizureDeviceSensorData(BaseModel):
    device_id: str
    accel_x: float
    accel_y: float
    accel_z: float
    gyro_x: float
    gyro_y: float
    gyro_z: float
    battery_percent: int
    seizure_flag: bool

class SeizureWindowReading(BaseModel):
    ax: float
    ay: float
    az: float
    gx: float
    gy: float
    gz: float
    bp: int

class SeizureWindowDevice(BaseModel):
    device_id: str
    seizure_flag: bool
    readings: List[SeizureWindowReading]

class SeizureEventPayload(BaseModel):
    type: str
    start_time_ut: int
    end_time_ut: int
    duration_seconds: int
    time_valid: Optional[bool] = True
    device_ids: List[str]
    seizing_devices: List[str]
    sensor_data: List[SeizureDeviceSensorData]
    window_data: Optional[List[SeizureWindowDevice]] = None


# =====================================================================
# AUTH HELPERS
# =====================================================================
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_user_by_username(username: str):
    return await database.fetch_one(users.select().where(users.c.username == username))

async def authenticate_user(username: str, password: str):
    user = await get_user_by_username(username)
    if not user or user["password"] != password:
        return False
    return user

async def get_current_user(token: str = Depends(oauth2_scheme)):
    exc = HTTPException(status_code=401, detail="Invalid or expired token")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise exc
    except JWTError:
        raise exc
    user = await get_user_by_username(username)
    if not user:
        raise exc
    return user

async def get_active_device_seizure(device_id: str):
    return await database.fetch_one(
        device_seizure_sessions.select()
        .where(device_seizure_sessions.c.device_id == device_id)
        .where(device_seizure_sessions.c.end_time == None)
        .order_by(device_seizure_sessions.c.start_time.desc())
    )

async def get_active_user_seizure(user_id: int, seizure_type: str):
    return await database.fetch_one(
        user_seizure_sessions.select()
        .where(user_seizure_sessions.c.user_id == user_id)
        .where(user_seizure_sessions.c.type == seizure_type)
        .where(user_seizure_sessions.c.end_time == None)
        .order_by(user_seizure_sessions.c.start_time.desc())
    )

async def get_recent_completed_gtcs(user_id: int, now_utc: datetime) -> bool:
    cutoff = now_utc - timedelta(seconds=RECENT_GTCS_SUPPRESS_JERK_SECONDS)
    row = await database.fetch_one(
        user_seizure_sessions.select()
        .where(user_seizure_sessions.c.user_id == user_id)
        .where(user_seizure_sessions.c.type == "GTCS")
        .where(user_seizure_sessions.c.end_time != None)
        .where(user_seizure_sessions.c.end_time >= cutoff)
        .order_by(user_seizure_sessions.c.end_time.desc())
        .limit(1)
    )
    return row is not None

# =====================================================================
# count_recent_seizure_readings()
#
# Returns 1 if this device has uploaded seizure_flag=True within
# SEIZURE_WINDOW_SECONDS. This is how we handle upload stagger:
# device A uploaded True 3s ago, device B uploads True now — both
# count because A's reading is still within the 7s window.
# =====================================================================
async def count_recent_seizure_readings(device_id: str, now_utc: datetime) -> int:
    cutoff = now_utc - timedelta(seconds=SEIZURE_WINDOW_SECONDS)
    row = await database.fetch_one(
        sensor_data.select()
        .where(sensor_data.c.device_id == device_id)
        .where(sensor_data.c.timestamp >= cutoff)
        .where(sensor_data.c.seizure_flag == True)
        .order_by(sensor_data.c.timestamp.desc())
        .limit(1)
    )
    return 1 if row else 0

# =====================================================================
# get_continuous_seizure_start()
#
# Walk backwards from now to find when the CURRENT continuous bout of
# motion actually started. Stop when gap between readings > SEIZURE_WINDOW.
# Cap lookback to max threshold + buffer to prevent stale inflation.
# =====================================================================
async def get_continuous_seizure_start(device_id: str, now_utc: datetime) -> datetime:
    max_lookback_seconds = GTCS_THRESHOLD_1_DEVICE_SECONDS + 10  # 30s max
    lookback = now_utc - timedelta(seconds=max_lookback_seconds)
    rows = await database.fetch_all(
        sensor_data.select()
        .where(sensor_data.c.device_id == device_id)
        .where(sensor_data.c.timestamp >= lookback)
        .where(sensor_data.c.seizure_flag == True)
        .order_by(sensor_data.c.timestamp.desc())
    )
    if not rows:
        return now_utc
    earliest = rows[0]["timestamp"]
    for i in range(1, len(rows)):
        gap = (rows[i-1]["timestamp"] - rows[i]["timestamp"]).total_seconds()
        if gap <= SEIZURE_WINDOW_SECONDS:
            earliest = rows[i]["timestamp"]
        else:
            break
    return earliest

# =====================================================================
# get_recent_seizure_data()
#
# Returns count of devices currently seizing (within SEIZURE_WINDOW)
# and the earliest continuous start time per device.
# =====================================================================
async def get_recent_seizure_data(device_ids: list, now_utc: datetime):
    devices_with_seizure = 0
    device_seizure_counts = {}
    device_seizure_starts = {}

    for device_id in device_ids:
        count = await count_recent_seizure_readings(device_id, now_utc)
        device_seizure_counts[device_id] = count
        if count > 0:
            devices_with_seizure += 1
            start_time = await get_continuous_seizure_start(device_id, now_utc)
            device_seizure_starts[device_id] = start_time

    return {
        'devices_with_seizure': devices_with_seizure,
        'device_seizure_counts': device_seizure_counts,
        'device_seizure_starts': device_seizure_starts,
    }

async def close_stale_sessions(user_id: int, device_ids: list, now_utc: datetime):
    stale_cutoff = now_utc - timedelta(seconds=STALE_SESSION_THRESHOLD_SECONDS)
    for device_id in device_ids:
        stale_device_sessions = await database.fetch_all(
            device_seizure_sessions.select()
            .where(device_seizure_sessions.c.device_id == device_id)
            .where(device_seizure_sessions.c.end_time == None)
            .where(device_seizure_sessions.c.start_time < stale_cutoff)
        )
        for s in stale_device_sessions:
            print(f"[STALE] Closing stale device session id={s['id']} device={device_id}")
            await database.execute(
                device_seizure_sessions.update()
                .where(device_seizure_sessions.c.id == s["id"])
                .values(end_time=now_utc)
            )
    for stype in ["Jerk", "GTCS"]:
        stale_user_sessions = await database.fetch_all(
            user_seizure_sessions.select()
            .where(user_seizure_sessions.c.user_id == user_id)
            .where(user_seizure_sessions.c.type == stype)
            .where(user_seizure_sessions.c.end_time == None)
            .where(user_seizure_sessions.c.start_time < stale_cutoff)
        )
        for s in stale_user_sessions:
            print(f"[STALE] Closing stale {stype} session id={s['id']} user={user_id}")
            await database.execute(
                user_seizure_sessions.update()
                .where(user_seizure_sessions.c.id == s["id"])
                .values(end_time=now_utc)
            )

async def delete_jerk_events_near_time(user_id: int, near_time: datetime, tolerance_seconds: int = 60):
    cutoff_start = near_time - timedelta(seconds=tolerance_seconds)
    cutoff_end   = near_time + timedelta(seconds=tolerance_seconds)
    jerk_events = await database.fetch_all(
        user_seizure_sessions.select()
        .where(user_seizure_sessions.c.user_id == user_id)
        .where(user_seizure_sessions.c.type == "Jerk")
        .where(user_seizure_sessions.c.start_time >= cutoff_start)
        .where(user_seizure_sessions.c.start_time <= cutoff_end)
    )
    deleted = 0
    for j in jerk_events:
        print(f"[CLEANUP] Deleting Jerk id={j['id']} (escalated to GTCS)")
        await database.execute(
            user_seizure_sessions.delete()
            .where(user_seizure_sessions.c.id == j["id"])
        )
        deleted += 1
    if deleted:
        print(f"[CLEANUP] Deleted {deleted} Jerk event(s) near {ts_pht_iso(near_time)}")


# =====================================================================
# APP
# =====================================================================
app = FastAPI(title="Seizure Monitor Backend v21")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
async def startup():
    await database.connect()
    for col_sql, col_name in [
        ("ALTER TABLE user_seizure_sessions ADD COLUMN duration_seconds INTEGER", "duration_seconds"),
        ("ALTER TABLE user_seizure_sessions ADD COLUMN seizing_devices TEXT", "seizing_devices"),
    ]:
        try:
            await database.execute(col_sql)
            print(f"[STARTUP] Added column: {col_name}")
        except Exception as e:
            print(f"[STARTUP] Column '{col_name}' already exists (ok)")

    print("[STARTUP] Closing stale sessions...")
    now_utc = datetime.now(timezone.utc)
    stale_cutoff = now_utc - timedelta(seconds=STALE_SESSION_THRESHOLD_SECONDS)

    stale_device = await database.fetch_all(
        device_seizure_sessions.select()
        .where(device_seizure_sessions.c.end_time == None)
        .where(device_seizure_sessions.c.start_time < stale_cutoff)
    )
    for s in stale_device:
        await database.execute(
            device_seizure_sessions.update()
            .where(device_seizure_sessions.c.id == s["id"])
            .values(end_time=now_utc)
        )

    stale_user = await database.fetch_all(
        user_seizure_sessions.select()
        .where(user_seizure_sessions.c.end_time == None)
        .where(user_seizure_sessions.c.start_time < stale_cutoff)
    )
    for s in stale_user:
        await database.execute(
            user_seizure_sessions.update()
            .where(user_seizure_sessions.c.id == s["id"])
            .values(end_time=now_utc)
        )
    print(f"[STARTUP] Cleaned {len(stale_device)} device + {len(stale_user)} user stale sessions")

@app.on_event("shutdown")
async def shutdown():
    await database.disconnect()

@app.get("/api/health")
async def health():
    return {"status": "ok"}

@app.api_route("/", methods=["GET", "HEAD"])
async def root():
    return {"message": "Seizure Monitor Backend v21"}


# =====================================================================
# AUTH
# =====================================================================
@app.post("/api/register")
async def register(u: UserCreate):
    if await get_user_by_username(u.username):
        raise HTTPException(status_code=400, detail="Username already exists")
    user_id = await database.execute(
        users.insert().values(username=u.username, password=u.password, is_admin=u.is_admin)
    )
    return {"id": user_id, "username": u.username}

@app.post("/api/login", response_model=Token)
async def login(body: LoginRequest):
    user = await authenticate_user(body.username, body.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid username or password.")
    token = create_access_token(
        {"sub": user["username"], "is_admin": user["is_admin"]},
        timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
    )
    return {"access_token": token, "token_type": "bearer"}

@app.get("/api/me")
async def get_me(current_user=Depends(get_current_user)):
    return {
        "id": current_user["id"],
        "username": current_user["username"],
        "is_admin": current_user["is_admin"],
    }


# =====================================================================
# DEVICES
# =====================================================================
@app.post("/api/devices/register")
async def register_device(d: DeviceRegister, current_user=Depends(get_current_user)):
    my_devices = await database.fetch_all(
        devices.select().where(devices.c.user_id == current_user["id"])
    )
    if len(my_devices) >= 3:
        raise HTTPException(status_code=400, detail="Max 3 devices allowed")
    if await database.fetch_one(devices.select().where(devices.c.device_id == d.device_id)):
        raise HTTPException(status_code=400, detail="Device ID already exists")
    await database.execute(
        devices.insert().values(
            user_id=current_user["id"],
            device_id=d.device_id,
            label=d.label or d.device_id
        )
    )
    return {"status": "ok", "device_id": d.device_id}

@app.get("/api/devices")
async def get_user_devices(current_user=Depends(get_current_user)):
    rows = await database.fetch_all(
        devices.select().where(devices.c.user_id == current_user["id"])
    )
    result = []
    cutoff_time = datetime.now(timezone.utc) - timedelta(seconds=CONNECTED_THRESHOLD_SECONDS)
    for row in rows:
        latest = await database.fetch_one(
            sensor_data.select()
            .where(sensor_data.c.device_id == row["device_id"])
            .order_by(sensor_data.c.timestamp.desc())
            .limit(1)
        )
        connected = False; battery = 0; last_sync_display = None
        accel_x = accel_y = accel_z = gyro_x = gyro_y = gyro_z = 0.0
        seizure_flag = False
        if latest:
            connected = latest["timestamp"] >= cutoff_time
            battery = latest["battery_percent"]
            last_sync_display = to_pht(latest["timestamp"]).strftime("%I:%M %p")
            accel_x = latest["accel_x"] or 0.0; accel_y = latest["accel_y"] or 0.0
            accel_z = latest["accel_z"] or 0.0; gyro_x = latest["gyro_x"] or 0.0
            gyro_y = latest["gyro_y"] or 0.0; gyro_z = latest["gyro_z"] or 0.0
            seizure_flag = latest["seizure_flag"] or False
        result.append({
            "id": row["id"], "device_id": row["device_id"], "label": row["label"],
            "connected": connected, "battery_percent": battery,
            "last_sync_display": last_sync_display,
            "accel_x": accel_x, "accel_y": accel_y, "accel_z": accel_z,
            "gyro_x": gyro_x, "gyro_y": gyro_y, "gyro_z": gyro_z,
            "seizure_flag": seizure_flag,
        })
    return result

@app.get("/api/mydevices_with_latest_data")
async def get_my_devices_with_latest(current_user=Depends(get_current_user)):
    user_devices = await database.fetch_all(
        devices.select().where(devices.c.user_id == current_user["id"])
    )
    output = []
    now = datetime.now(PHT)
    cutoff_time = datetime.now(timezone.utc) - timedelta(seconds=CONNECTED_THRESHOLD_SECONDS)
    for d in user_devices:
        latest = await database.fetch_one(
            sensor_data.select()
            .where(sensor_data.c.device_id == d["device_id"])
            .order_by(sensor_data.c.timestamp.desc())
            .limit(1)
        )
        connected = False; last_sync_val = None
        accel_x = accel_y = accel_z = gyro_x = gyro_y = gyro_z = 0.0
        battery = 0; seizure_flag = False
        if latest:
            connected = latest["timestamp"] >= cutoff_time
            battery = latest["battery_percent"]
            seizure_flag = latest["seizure_flag"] or False
            accel_x = latest["accel_x"] or 0.0; accel_y = latest["accel_y"] or 0.0
            accel_z = latest["accel_z"] or 0.0; gyro_x = latest["gyro_x"] or 0.0
            gyro_y = latest["gyro_y"] or 0.0; gyro_z = latest["gyro_z"] or 0.0
            ts_ph = to_pht(latest["timestamp"])
            diff = (now - ts_ph).total_seconds()
            last_sync_val = "Just now" if diff <= 10 else ts_ph.strftime("%I:%M %p")
        output.append({
            "device_id": d["device_id"], "label": d["label"],
            "battery_percent": battery, "last_sync": last_sync_val, "connected": connected,
            "accel_x": accel_x, "accel_y": accel_y, "accel_z": accel_z,
            "gyro_x": gyro_x, "gyro_y": gyro_y, "gyro_z": gyro_z,
            "seizure_flag": seizure_flag,
        })
    return output

@app.put("/api/devices/{device_id}")
async def update_device(device_id: str, update: DeviceUpdate, current_user=Depends(get_current_user)):
    row = await database.fetch_one(
        devices.select()
        .where(devices.c.device_id == device_id)
        .where(devices.c.user_id == current_user["id"])
    )
    if not row:
        raise HTTPException(status_code=404, detail="Device not found")
    await database.execute(
        devices.update().where(devices.c.device_id == device_id).values(label=update.label)
    )
    return {"message": "Device updated"}

@app.delete("/api/devices/{device_id}")
async def delete_device(device_id: str, current_user=Depends(get_current_user)):
    row = await database.fetch_one(
        devices.select()
        .where(devices.c.device_id == device_id)
        .where(devices.c.user_id == current_user["id"])
    )
    if not row:
        raise HTTPException(status_code=404, detail="Device not found")
    await database.execute(devices.delete().where(devices.c.device_id == device_id))
    return {"message": "Device deleted"}


# =====================================================================
# SEIZURE EVENTS — READ ENDPOINTS
# =====================================================================
def compute_duration(row) -> Optional[int]:
    stored = row["duration_seconds"] if "duration_seconds" in row.keys() else None
    if stored is not None and stored > 0:
        return stored
    if row["end_time"] and row["start_time"]:
        diff = int((row["end_time"] - row["start_time"]).total_seconds())
        if diff > 0:
            return diff
    return stored

def parse_seizing_devices(row) -> List[str]:
    try:
        val = row["seizing_devices"] if "seizing_devices" in row.keys() else None
        if val:
            return json.loads(val)
    except Exception:
        pass
    return []

@app.get("/api/seizure_events/latest")
async def get_latest_event(current_user=Depends(get_current_user)):
    for stype in ["GTCS", "Jerk"]:
        row = await database.fetch_one(
            user_seizure_sessions.select()
            .where(user_seizure_sessions.c.user_id == current_user["id"])
            .where(user_seizure_sessions.c.type == stype)
            .where(user_seizure_sessions.c.end_time == None)
            .order_by(user_seizure_sessions.c.start_time.desc())
            .limit(1)
        )
        if row:
            return {
                "type": row["type"],
                "start": ts_pht_iso(row["start_time"]),
                "end": ts_pht_iso(row["end_time"]) if row["end_time"] else None,
                "duration_seconds": compute_duration(row),
                "seizing_devices": parse_seizing_devices(row),
            }
    row = await database.fetch_one(
        user_seizure_sessions.select()
        .where(user_seizure_sessions.c.user_id == current_user["id"])
        .order_by(user_seizure_sessions.c.start_time.desc())
        .limit(1)
    )
    if not row:
        return {}
    return {
        "type": row["type"],
        "start": ts_pht_iso(row["start_time"]),
        "end": ts_pht_iso(row["end_time"]) if row["end_time"] else None,
        "duration_seconds": compute_duration(row),
        "seizing_devices": parse_seizing_devices(row),
    }

@app.get("/api/seizure_events/all")
async def get_all_seizure_events(current_user=Depends(get_current_user)):
    rows = await database.fetch_all(
        user_seizure_sessions.select()
        .where(user_seizure_sessions.c.user_id == current_user["id"])
        .order_by(user_seizure_sessions.c.start_time.desc())
    )
    return [
        {
            "type": r["type"],
            "start": ts_pht_iso(r["start_time"]),
            "end": ts_pht_iso(r["end_time"]) if r["end_time"] else None,
            "duration_seconds": compute_duration(r),
            "seizing_devices": parse_seizing_devices(r),
        }
        for r in rows
    ]

@app.get("/api/seizure_events/download")
async def download_seizure_events(current_user=Depends(get_current_user)):
    rows = await database.fetch_all(
        user_seizure_sessions.select()
        .where(user_seizure_sessions.c.user_id == current_user["id"])
        .order_by(user_seizure_sessions.c.start_time.desc())
    )
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Type", "Start Time (PHT)", "End Time (PHT)", "Duration (seconds)", "Seizing Devices"])
    for r in rows:
        start = ts_pht_iso(r["start_time"])
        end = ts_pht_iso(r["end_time"]) if r["end_time"] else "Ongoing"
        duration = compute_duration(r) or ""
        seizing = ", ".join(parse_seizing_devices(r))
        writer.writerow([r["type"], start, end, duration, seizing])
    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=seizure_events.csv"}
    )

@app.get("/api/seizure_events")
async def get_seizure_events(current_user=Depends(get_current_user)):
    rows = await database.fetch_all(
        user_seizure_sessions.select()
        .where(user_seizure_sessions.c.user_id == current_user["id"])
        .order_by(user_seizure_sessions.c.start_time.desc())
    )
    return [
        {
            "type": r["type"],
            "start": ts_pht_iso(r["start_time"]),
            "end": ts_pht_iso(r["end_time"]) if r["end_time"] else None,
            "seizing_devices": parse_seizing_devices(r),
        }
        for r in rows
    ]

@app.get("/api/latest_seizure_event")
async def get_latest_seizure_event(current_user=Depends(get_current_user)):
    row = await database.fetch_one(
        user_seizure_sessions.select()
        .where(user_seizure_sessions.c.user_id == current_user["id"])
        .order_by(user_seizure_sessions.c.start_time.desc())
        .limit(1)
    )
    if not row:
        return None
    return {
        "type": row["type"],
        "start_time": ts_pht_iso(row["start_time"]),
        "end_time": ts_pht_iso(row["end_time"]),
        "duration_seconds": compute_duration(row),
        "seizing_devices": parse_seizing_devices(row),
    }


# =====================================================================
# ESP32 UPLOAD — raw sensor reading (/api/device/upload)
#
# FLOW:
# 1. Save sensor reading to DB
# 2. Count devices with recent seizure_flag=True (within SEIZURE_WINDOW_SECONDS)
# 3. If devices_with_seizure >= 1:
#    a. If no active GTCS: check motion duration. If >= threshold → open GTCS.
#    b. If active GTCS: keep it open (reset grace timer).
# 4. If devices_with_seizure == 0:
#    a. If active GTCS: start/continue grace period
#    b. After grace: close GTCS with duration = trigger_time → motion_lost_time
# =====================================================================
@app.post("/api/device/upload")
async def upload_device_data(payload: UnifiedESP32Payload):
    existing = await database.fetch_one(
        devices.select().where(devices.c.device_id == payload.device_id)
    )
    if not existing:
        raise HTTPException(status_code=404, detail=f"Device {payload.device_id} not registered")

    ts_utc = parse_esp32_timestamp(payload.timestamp_ms)
    print(f"[UPLOAD] device={payload.device_id} | seizure={payload.seizure_flag} | ts={to_pht(ts_utc).strftime('%H:%M:%S PHT')}")

    await database.execute(sensor_data.insert().values(
        device_id=payload.device_id,
        timestamp=ts_utc,
        accel_x=payload.accel_x, accel_y=payload.accel_y, accel_z=payload.accel_z,
        gyro_x=payload.gyro_x, gyro_y=payload.gyro_y, gyro_z=payload.gyro_z,
        battery_percent=payload.battery_percent,
        seizure_flag=payload.seizure_flag
    ))

    await database.execute(device_data.insert().values(
        device_id=payload.device_id,
        timestamp=ts_utc,
        payload=json.dumps({
            "accel_x": payload.accel_x, "accel_y": payload.accel_y, "accel_z": payload.accel_z,
            "gyro_x": payload.gyro_x, "gyro_y": payload.gyro_y, "gyro_z": payload.gyro_z,
            "battery_percent": payload.battery_percent,
            "seizure_flag": payload.seizure_flag,
        })
    ))

    user_id = existing["user_id"]
    user_devices = await database.fetch_all(
        devices.select().where(devices.c.user_id == user_id)
    )
    device_ids = [d["device_id"] for d in user_devices]
    now_utc = datetime.now(timezone.utc)

    await close_stale_sessions(user_id, device_ids, now_utc)

    # ----------------------------------------------------------------
    # Device seizure session management (for tracking purposes)
    # ----------------------------------------------------------------
    active_device = await get_active_device_seizure(payload.device_id)
    if payload.seizure_flag:
        if not active_device:
            # Check if a recent session closed within SEIZURE_WINDOW — reopen it
            recent_closed = await database.fetch_one(
                device_seizure_sessions.select()
                .where(device_seizure_sessions.c.device_id == payload.device_id)
                .where(device_seizure_sessions.c.end_time != None)
                .where(device_seizure_sessions.c.end_time >= now_utc - timedelta(seconds=SEIZURE_WINDOW_SECONDS))
                .order_by(device_seizure_sessions.c.end_time.desc())
                .limit(1)
            )
            if recent_closed:
                await database.execute(
                    device_seizure_sessions.update()
                    .where(device_seizure_sessions.c.id == recent_closed["id"])
                    .values(end_time=None)
                )
            else:
                await database.execute(
                    device_seizure_sessions.insert().values(
                        device_id=payload.device_id, start_time=ts_utc, end_time=None
                    )
                )
    else:
        if active_device:
            await database.execute(
                device_seizure_sessions.update()
                .where(device_seizure_sessions.c.id == active_device["id"])
                .values(end_time=now_utc)
            )

    # ----------------------------------------------------------------
    # Count devices currently seizing (time-window based)
    # ----------------------------------------------------------------
    seizure_data = await get_recent_seizure_data(device_ids, now_utc)
    devices_with_seizure = seizure_data['devices_with_seizure']
    device_seizure_counts = seizure_data['device_seizure_counts']
    device_seizure_starts = seizure_data['device_seizure_starts']

    print(f"[DETECTION] user={user_id} | devices_with_seizure={devices_with_seizure}/{len(device_ids)} | counts={device_seizure_counts}")

    active_jerk = await get_active_user_seizure(user_id, "Jerk")
    active_gtcs = await get_active_user_seizure(user_id, "GTCS")

    # ================================================================
    # JERK PATH
    # ================================================================
    if active_jerk:
        jerk_age = (now_utc - active_jerk["start_time"]).total_seconds()

        if jerk_age >= JERK_TO_GTCS_ESCALATION_SECONDS and devices_with_seizure >= 1:
            print(f"[JERK→GTCS] ESCALATING (age={jerk_age:.1f}s)")
            await delete_jerk_events_near_time(user_id, active_jerk["start_time"], tolerance_seconds=60)
            seizing_device_ids = [did for did in device_ids if device_seizure_counts.get(did, 0) > 0]
            if not seizing_device_ids:
                seizing_device_ids = device_ids
            await database.execute(user_seizure_sessions.insert().values(
                user_id=user_id, type="GTCS",
                start_time=active_jerk["start_time"], end_time=None,
                seizing_devices=json.dumps(seizing_device_ids)
            ))
            _jerk_suppress_until.pop(user_id, None)
            return {"status": "saved", "event": "GTCS_escalated"}

        elif jerk_age >= JERK_FIXED_DURATION_SECONDS:
            print(f"[JERK] AUTO-CLOSE (age={jerk_age:.1f}s)")
            await database.execute(
                user_seizure_sessions.update()
                .where(user_seizure_sessions.c.id == active_jerk["id"])
                .values(end_time=now_utc, duration_seconds=int(jerk_age))
            )
            active_jerk = None
            _jerk_suppress_until[user_id] = now_utc + timedelta(seconds=JERK_REOPEN_SUPPRESS_SECONDS)

        else:
            print(f"[JERK] Continuing (id={active_jerk['id']}, age={jerk_age:.1f}s)")
            return {"status": "saved", "event": "Jerk"}

    # Open new Jerk session when all 3 devices spike
    if devices_with_seizure >= 3 and not active_jerk and not active_gtcs:
        jerk_suppress = _jerk_suppress_until.get(user_id)
        if jerk_suppress and now_utc < jerk_suppress:
            remaining = (jerk_suppress - now_utc).total_seconds()
            print(f"[JERK] Re-open suppressed ({remaining:.1f}s remaining)")
        else:
            _jerk_suppress_until.pop(user_id, None)
            recent_gtcs_exists = await get_recent_completed_gtcs(user_id, now_utc)
            if recent_gtcs_exists:
                print(f"[JERK] SUPPRESSED — recent GTCS exists")
                return {"status": "saved", "event": "suppressed_jerk"}

            seizing_device_ids = [did for did in device_ids if device_seizure_counts.get(did, 0) > 0]
            if not seizing_device_ids:
                seizing_device_ids = device_ids
            jerk_start_time = min(
                [device_seizure_starts[did] for did in seizing_device_ids if did in device_seizure_starts],
                default=ts_utc
            )
            print(f"[JERK] NEW SESSION start={to_pht(jerk_start_time).strftime('%H:%M:%S PHT')}")
            await database.execute(user_seizure_sessions.insert().values(
                user_id=user_id, type="Jerk",
                start_time=jerk_start_time, end_time=None,
                seizing_devices=json.dumps(seizing_device_ids)
            ))
            return {"status": "saved", "event": "Jerk"}

    # ================================================================
    # GTCS PATH B — sustained motion from 1+ devices
    #
    # KEY RULE: Motion stops = seizure closes (after grace).
    # Duration = trigger_time → motion_lost_time (NOT wall clock).
    # ================================================================
    if devices_with_seizure >= 1:
        # [FIX 1] Clear grace timer since motion is still active
        active_gtcs_check = await get_active_user_seizure(user_id, "GTCS")
        if active_gtcs_check:
            # Motion still present — reset grace timer and keep going
            _gtcs_motion_lost_time.pop(user_id, None)
            print(f"[GTCS PATH B] Continuing (id={active_gtcs_check['id']}, devices={devices_with_seizure})")
            return {"status": "saved", "event": "GTCS"}

        # No active GTCS — check if motion has been long enough to trigger one
        gtcs_threshold = (GTCS_THRESHOLD_MULTI_DEVICE_SECONDS
                          if devices_with_seizure >= 2
                          else GTCS_THRESHOLD_1_DEVICE_SECONDS)

        seizing_device_ids = [did for did in device_ids if device_seizure_counts.get(did, 0) > 0]
        if seizing_device_ids:
            oldest_start = min(
                [device_seizure_starts[did] for did in seizing_device_ids if did in device_seizure_starts],
                default=now_utc
            )
            motion_duration = (now_utc - oldest_start).total_seconds()
            print(f"[GTCS PATH B] motion={motion_duration:.1f}s | threshold={gtcs_threshold}s | devices={devices_with_seizure}")

            if motion_duration >= gtcs_threshold:
                print(f"[GTCS PATH B] *** TRIGGERED ***")
                # Record trigger time for accurate duration calculation
                _gtcs_motion_started[user_id] = now_utc
                await database.execute(user_seizure_sessions.insert().values(
                    user_id=user_id, type="GTCS",
                    start_time=oldest_start, end_time=None,
                    seizing_devices=json.dumps(seizing_device_ids)
                ))
                return {"status": "saved", "event": "GTCS"}
            else:
                print(f"[GTCS PATH B] Timer running ({motion_duration:.1f}s / {gtcs_threshold}s)")

        return {"status": "saved", "event": "none"}

    # ================================================================
    # devices_with_seizure == 0 — no motion detected
    # [FIX 1] Close GTCS after grace period.
    # Duration = trigger_time → motion_lost_time (not now).
    # ================================================================
    active_gtcs = await get_active_user_seizure(user_id, "GTCS")
    if active_gtcs:
        if user_id not in _gtcs_motion_lost_time:
            # First upload with no motion — start grace period
            _gtcs_motion_lost_time[user_id] = now_utc
            print(f"[GTCS] Motion absent — grace started ({GTCS_BACKEND_GRACE_SECONDS}s)")
            return {"status": "saved", "event": "GTCS_grace"}

        time_absent = (now_utc - _gtcs_motion_lost_time[user_id]).total_seconds()

        if time_absent < GTCS_BACKEND_GRACE_SECONDS:
            print(f"[GTCS] Grace active ({time_absent:.1f}s / {GTCS_BACKEND_GRACE_SECONDS}s)")
            return {"status": "saved", "event": "GTCS_grace"}

        # Grace expired — close GTCS
        motion_lost = _gtcs_motion_lost_time.pop(user_id, now_utc)
        motion_started = _gtcs_motion_started.pop(user_id, None)

        # [FIX 2] Duration = trigger_time → motion_lost_time
        # This is the actual seizure window — from when GTCS was detected
        # to when motion actually stopped. Excludes the grace wait time.
        if motion_started and motion_lost > motion_started:
            gtcs_duration = (motion_lost - motion_started).total_seconds()
            print(f"[GTCS] Duration: trigger={to_pht(motion_started).strftime('%H:%M:%S')} → stop={to_pht(motion_lost).strftime('%H:%M:%S')} = {gtcs_duration:.1f}s")
        else:
            # Fallback: session open → motion lost
            gtcs_duration = (motion_lost - active_gtcs["start_time"]).total_seconds()
            print(f"[GTCS] Duration (fallback): {gtcs_duration:.1f}s")

        gtcs_duration = max(0, gtcs_duration)

        if gtcs_duration >= MIN_GTCS_DURATION_SECONDS:
            print(f"[GTCS] CLOSING — duration={gtcs_duration:.1f}s")
            await database.execute(
                user_seizure_sessions.update()
                .where(user_seizure_sessions.c.id == active_gtcs["id"])
                .values(end_time=motion_lost, duration_seconds=int(gtcs_duration))
            )
        else:
            print(f"[GTCS] Too short ({gtcs_duration:.1f}s < min {MIN_GTCS_DURATION_SECONDS}s) — deleting")
            await database.execute(
                user_seizure_sessions.delete()
                .where(user_seizure_sessions.c.id == active_gtcs["id"])
            )
    else:
        # No active GTCS — clean up any stale state
        _gtcs_motion_lost_time.pop(user_id, None)
        _gtcs_motion_started.pop(user_id, None)

    return {"status": "saved", "event": "none"}


# =====================================================================
# ESP32 UPLOAD — seizure event from SD card (/api/device/upload_seizure_event)
#
# This is called when ESP32 had WiFi down during a seizure and saved
# to SD, then WiFi came back up and it's flushing the SD queue.
#
# [FIX 3] KEY RULE: Check for duplicate FIRST.
# If PATH B already wrote a session with the same approximate start time,
# this SD upload is a duplicate — skip it.
# Only write if no duplicate exists.
# =====================================================================
@app.post("/api/device/upload_seizure_event")
async def upload_seizure_event(payload: SeizureEventPayload):
    if not payload.device_ids:
        raise HTTPException(status_code=400, detail="device_ids is empty")

    first_device = await database.fetch_one(
        devices.select().where(devices.c.device_id == payload.device_ids[0])
    )
    if not first_device:
        raise HTTPException(status_code=404, detail=f"Device {payload.device_ids[0]} not registered")
    user_id = first_device["user_id"]

    time_valid = payload.time_valid if payload.time_valid is not None else True
    if not time_valid:
        print(f"[SD UPLOAD] REJECTED — time_valid=False")
        return {"status": "rejected", "reason": "boot_relative_timestamps_not_accepted"}

    start_utc = parse_unix_seconds(payload.start_time_ut)
    end_utc   = parse_unix_seconds(payload.end_time_ut)

    duration_sec = payload.duration_seconds
    if duration_sec <= 0:
        computed = int((end_utc - start_utc).total_seconds())
        duration_sec = max(1, computed)

    if end_utc <= start_utc and duration_sec > 0:
        end_utc = start_utc + timedelta(seconds=duration_sec)

    print(f"[SD UPLOAD] user={user_id} type={payload.type} "
          f"start={to_pht(start_utc).strftime('%Y-%m-%d %H:%M:%S PHT')} "
          f"dur={duration_sec}s")

    # [FIX 3] Check for duplicate — PATH B may have already written this session.
    tolerance = timedelta(seconds=30)
    existing_session = await database.fetch_one(
        user_seizure_sessions.select()
        .where(user_seizure_sessions.c.user_id == user_id)
        .where(user_seizure_sessions.c.type == payload.type)
        .where(user_seizure_sessions.c.start_time >= start_utc - tolerance)
        .where(user_seizure_sessions.c.start_time <= start_utc + tolerance)
    )
    if existing_session:
        print(f"[SD UPLOAD] Duplicate (id={existing_session['id']}) — skipping")
        return {"status": "duplicate", "event": payload.type}

    # No duplicate — this is a genuine offline event. Write it.
    now_utc = datetime.now(timezone.utc)

    # Close any open real-time sessions (they would be stale at this point)
    open_jerk = await get_active_user_seizure(user_id, "Jerk")
    if open_jerk:
        print(f"[SD UPLOAD] Closing stale real-time Jerk (id={open_jerk['id']})")
        await database.execute(
            user_seizure_sessions.delete()
            .where(user_seizure_sessions.c.id == open_jerk["id"])
        )

    open_gtcs = await get_active_user_seizure(user_id, "GTCS")
    if open_gtcs:
        print(f"[SD UPLOAD] Closing stale real-time GTCS (id={open_gtcs['id']})")
        await database.execute(
            user_seizure_sessions.delete()
            .where(user_seizure_sessions.c.id == open_gtcs["id"])
        )

    if payload.type == "GTCS":
        await delete_jerk_events_near_time(user_id, start_utc, tolerance_seconds=60)

    # Clean up in-memory state
    _gtcs_motion_lost_time.pop(user_id, None)
    _gtcs_motion_started.pop(user_id, None)
    _jerk_suppress_until.pop(user_id, None)

    seizing_json = json.dumps(payload.seizing_devices) if payload.seizing_devices else json.dumps(payload.device_ids)

    await database.execute(
        user_seizure_sessions.insert().values(
            user_id=user_id, type=payload.type,
            start_time=start_utc, end_time=end_utc,
            duration_seconds=duration_sec,
            seizing_devices=seizing_json,
        )
    )

    # Save sensor data for this event
    if payload.window_data:
        for dev_idx, wd in enumerate(payload.window_data):
            dev = await database.fetch_one(devices.select().where(devices.c.device_id == wd.device_id))
            if not dev or dev["user_id"] != user_id:
                continue
            num_readings = len(wd.readings)
            if num_readings == 0:
                continue
            device_offset = timedelta(milliseconds=200 * dev_idx)
            for idx, reading in enumerate(wd.readings):
                offset_sec = (duration_sec * idx) / max(num_readings - 1, 1)
                row_ts = start_utc + timedelta(seconds=offset_sec) + device_offset
                await database.execute(sensor_data.insert().values(
                    device_id=wd.device_id, timestamp=row_ts,
                    accel_x=reading.ax, accel_y=reading.ay, accel_z=reading.az,
                    gyro_x=reading.gx, gyro_y=reading.gy, gyro_z=reading.gz,
                    battery_percent=reading.bp, seizure_flag=wd.seizure_flag,
                ))
    else:
        SENSOR_ROW_INTERVAL_SEC = 2
        num_intervals = min(max(1, duration_sec // SENSOR_ROW_INTERVAL_SEC), 60)
        for dev_idx, sd_item in enumerate(payload.sensor_data):
            dev = await database.fetch_one(devices.select().where(devices.c.device_id == sd_item.device_id))
            if not dev or dev["user_id"] != user_id:
                continue
            device_offset = timedelta(milliseconds=500 * dev_idx)
            for idx in range(num_intervals + 1):
                offset_sec = (duration_sec * idx) / max(num_intervals, 1)
                row_ts = start_utc + timedelta(seconds=offset_sec) + device_offset
                await database.execute(sensor_data.insert().values(
                    device_id=sd_item.device_id, timestamp=row_ts,
                    accel_x=sd_item.accel_x, accel_y=sd_item.accel_y, accel_z=sd_item.accel_z,
                    gyro_x=sd_item.gyro_x, gyro_y=sd_item.gyro_y, gyro_z=sd_item.gyro_z,
                    battery_percent=sd_item.battery_percent, seizure_flag=sd_item.seizure_flag,
                ))

    print(f"[SD UPLOAD] Saved {payload.type} ({duration_sec}s)")
    return {
        "status": "saved",
        "event": payload.type,
        "duration_seconds": duration_sec,
        "start_pht": ts_pht_iso(start_utc),
        "end_pht": ts_pht_iso(end_utc),
        "seizing_devices": payload.seizing_devices,
        "time_valid": time_valid,
    }


# =====================================================================
# ADMIN ROUTES
# =====================================================================
@app.get("/api/users")
async def get_all_users(current_user=Depends(get_current_user)):
    if not current_user["is_admin"]:
        raise HTTPException(status_code=403, detail="Admins only")
    rows = await database.fetch_all(users.select())
    return [{"id": r["id"], "username": r["username"], "is_admin": r["is_admin"]} for r in rows]

@app.get("/api/admin/user/{user_id}/devices")
async def admin_get_user_devices(user_id: int, current_user=Depends(get_current_user)):
    if not current_user["is_admin"]:
        raise HTTPException(status_code=403, detail="Admins only")
    return await database.fetch_all(devices.select().where(devices.c.user_id == user_id))

@app.get("/api/admin/user/{user_id}/events")
async def admin_get_user_events(user_id: int, current_user=Depends(get_current_user)):
    if not current_user["is_admin"]:
        raise HTTPException(status_code=403, detail="Admins only")
    rows = await database.fetch_all(
        user_seizure_sessions.select()
        .where(user_seizure_sessions.c.user_id == user_id)
        .order_by(user_seizure_sessions.c.start_time.desc())
    )
    user_devices = await database.fetch_all(devices.select().where(devices.c.user_id == user_id))
    user_device_ids = [d["device_id"] for d in user_devices]
    result = []
    for r in rows:
        seizing_device_ids = parse_seizing_devices(r)
        if not seizing_device_ids:
            q = sensor_data.select().where(
                and_(sensor_data.c.device_id.in_(user_device_ids),
                     sensor_data.c.timestamp >= r["start_time"])
            )
            if r["end_time"]:
                q = q.where(sensor_data.c.timestamp <= r["end_time"])
            q = q.where(sensor_data.c.seizure_flag == True)
            seizing_rows = await database.fetch_all(q)
            seen = {}
            for sd in seizing_rows:
                if sd["device_id"] not in seen:
                    seen[sd["device_id"]] = True
            seizing_device_ids = list(seen.keys())
        result.append({
            "type": r["type"],
            "start": ts_pht_iso(r["start_time"]),
            "end": ts_pht_iso(r["end_time"]) if r["end_time"] else None,
            "duration_seconds": compute_duration(r),
            "device_id": seizing_device_ids[0] if seizing_device_ids else "",
            "device_ids": seizing_device_ids,
        })
    return result

@app.get("/api/admin/user/{user_id}/events/{start}/data")
async def get_event_sensor_data(
    user_id: int, start: str, end: Optional[str] = None,
    current_user=Depends(get_current_user)
):
    if not current_user["is_admin"]:
        raise HTTPException(status_code=403, detail="Admins only")
    start_dt_utc = datetime.fromisoformat(start).replace(tzinfo=PHT).astimezone(timezone.utc)
    end_dt_utc = datetime.fromisoformat(end).replace(tzinfo=PHT).astimezone(timezone.utc) if end else None
    user_devices = await database.fetch_all(devices.select().where(devices.c.user_id == user_id))
    device_ids = [d["device_id"] for d in user_devices]
    query = sensor_data.select().where(
        and_(sensor_data.c.device_id.in_(device_ids), sensor_data.c.timestamp >= start_dt_utc)
    )
    if end_dt_utc:
        query = query.where(sensor_data.c.timestamp <= end_dt_utc)
    rows = await database.fetch_all(query.order_by(sensor_data.c.timestamp.asc()))
    return [
        {
            "timestamp": ts_pht_iso(r["timestamp"]),
            "device_id": r["device_id"],
            "accel_x": r["accel_x"], "accel_y": r["accel_y"], "accel_z": r["accel_z"],
            "gyro_x": r["gyro_x"], "gyro_y": r["gyro_y"], "gyro_z": r["gyro_z"],
            "battery_percent": r["battery_percent"],
            "seizure_flag": r["seizure_flag"],
        }
        for r in rows
    ]

@app.delete("/api/delete_user/{user_id}")
async def delete_user(user_id: int, current_user=Depends(get_current_user)):
    if not current_user["is_admin"]:
        raise HTTPException(status_code=403, detail="Admins only")
    user = await database.fetch_one(users.select().where(users.c.id == user_id))
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    await database.execute(devices.delete().where(devices.c.user_id == user_id))
    await database.execute(users.delete().where(users.c.id == user_id))
    return {"detail": f"User {user['username']} deleted successfully"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
