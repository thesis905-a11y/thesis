# =====================================================================
# SEIZURE MONITOR BACKEND - v22
#
# ROOT CAUSE ANALYSIS of remaining bugs:
#
# BUG 1: "Biglang nagka-Jerk kahit hindi dapat"
#   CAUSE: upload_seizure_event (SD flush) was DELETING the active
#          real-time GTCS session (id=231) and replacing it with a
#          Jerk from the SD queue. This is completely wrong.
#   FIX:   If there is an ACTIVE (open) GTCS or Jerk session right now,
#          the SD upload is SKIPPED entirely — the real-time system is
#          already tracking correctly. SD uploads only matter when no
#          real-time session was opened (i.e. WiFi was down during seizure).
#
# BUG 2: "Antagal pa rin ng GTCS kahit 15-17s lang ginalaw"
#   CAUSE A: SEIZURE_WINDOW_SECONDS = 7s meant that even after all
#            devices uploaded False, they still "counted" as seizing
#            for up to 7 more seconds (because their last True reading
#            was within the window). This inflated both the motion
#            duration timer AND delayed closure.
#   CAUSE B: Grace period (3s) added MORE delay on top of the window.
#   CAUSE C: motion_lost_time was set to now_utc when the grace check
#            fired, not when motion actually stopped — inflating duration.
#
#   FIX:   REMOVE the seizure window entirely. Count a device as
#          "currently seizing" only if their LATEST reading in the DB
#          is seizure_flag=True AND it arrived within UPLOAD_FRESHNESS_S
#          (= 1 upload cycle = ~2s). This means:
#          - Device uploads False → immediately not counted (no 7s lag)
#          - All devices False → GTCS closes immediately (no grace)
#          - Duration = exact time from trigger to last True upload
#
#   TRADEOFF: Upload stagger (~1.2s between 3 devices) means there will
#             be brief moments where count drops from 2→1 mid-seizure.
#             This is handled by: only CLOSING when count=0, not when
#             count drops. Count 1 vs 2 only affects the threshold used.
#
# DESIGN PRINCIPLES (v22):
#   - A device is "currently seizing" iff its latest DB reading
#     (within UPLOAD_FRESHNESS_S) has seizure_flag=True.
#   - When ALL devices upload False → GTCS closes immediately.
#   - No grace period. No sticky window. No accumulation delay.
#   - Duration = trigger_time → time of last True upload (from DB).
#   - SD upload NEVER interrupts an active real-time session.
#   - SD upload only writes if no session exists near that time.
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
# UPLOAD FRESHNESS — how recent a reading must be to count as "current".
# Set to 3x upload interval (1.2s × 3 = 3.6s) to handle stagger.
# If a device's latest reading is older than this, it is NOT counted.
# This replaces the old SEIZURE_WINDOW_SECONDS (7s) approach.
# Shorter = faster close. 4s safely covers worst-case stagger.
# =====================================================================
UPLOAD_FRESHNESS_S = 4

# =====================================================================
# JERK THRESHOLDS
# =====================================================================
JERK_FIXED_DURATION_SECONDS     = 5
JERK_TO_GTCS_ESCALATION_SECONDS = 10
JERK_REOPEN_SUPPRESS_SECONDS    = 5

# =====================================================================
# GTCS THRESHOLDS (must match ESP32 v25)
# =====================================================================
GTCS_THRESHOLD_1_DEVICE_SECONDS     = 20
GTCS_THRESHOLD_MULTI_DEVICE_SECONDS = 15
RECENT_GTCS_SUPPRESS_JERK_SECONDS   = 60

# =====================================================================
# IN-MEMORY STATE
#
# WHY IN-MEMORY FOR MOTION TIMING (not DB-based):
# The gap between uploads from the same device is ~5s (1.2s interval
# × 3 devices + server processing). Any DB gap tolerance that works
# for chaining (>5s) would also count old False readings as True.
# In-memory tracking is immune to this — exactly like ESP32 does it.
# =====================================================================

# device_id → datetime when this device's current motion bout started.
# Set on first True upload. Cleared on False upload.
_device_motion_start: dict = {}

# user_id → datetime when GTCS threshold was first triggered.
# Duration = last True upload time - trigger time.
_gtcs_trigger_time: dict = {}

# user_id → datetime until new Jerk session is suppressed.
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

async def get_active_user_seizure(user_id: int, seizure_type: str):
    return await database.fetch_one(
        user_seizure_sessions.select()
        .where(user_seizure_sessions.c.user_id == user_id)
        .where(user_seizure_sessions.c.type == seizure_type)
        .where(user_seizure_sessions.c.end_time == None)
        .order_by(user_seizure_sessions.c.start_time.desc())
    )

async def get_any_active_user_seizure(user_id: int):
    """Returns any open seizure session (Jerk or GTCS)."""
    return await database.fetch_one(
        user_seizure_sessions.select()
        .where(user_seizure_sessions.c.user_id == user_id)
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

async def close_stale_sessions(user_id: int, device_ids: list, now_utc: datetime):
    stale_cutoff = now_utc - timedelta(seconds=STALE_SESSION_THRESHOLD_SECONDS)
    for device_id in device_ids:
        stale = await database.fetch_all(
            device_seizure_sessions.select()
            .where(device_seizure_sessions.c.device_id == device_id)
            .where(device_seizure_sessions.c.end_time == None)
            .where(device_seizure_sessions.c.start_time < stale_cutoff)
        )
        for s in stale:
            await database.execute(
                device_seizure_sessions.update()
                .where(device_seizure_sessions.c.id == s["id"])
                .values(end_time=now_utc)
            )
    for stype in ["Jerk", "GTCS"]:
        stale = await database.fetch_all(
            user_seizure_sessions.select()
            .where(user_seizure_sessions.c.user_id == user_id)
            .where(user_seizure_sessions.c.type == stype)
            .where(user_seizure_sessions.c.end_time == None)
            .where(user_seizure_sessions.c.start_time < stale_cutoff)
        )
        for s in stale:
            print(f"[STALE] Closing {stype} id={s['id']}")
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
    for j in jerk_events:
        print(f"[CLEANUP] Deleting Jerk id={j['id']} (escalated to GTCS)")
        await database.execute(
            user_seizure_sessions.delete()
            .where(user_seizure_sessions.c.id == j["id"])
        )

# =====================================================================
# is_device_currently_seizing()
#
# A device counts as "currently seizing" iff its most recent reading
# in sensor_data arrived within UPLOAD_FRESHNESS_S AND is True.
#
# WHY NO WINDOW:
# Old approach: count True readings within last 7s.
# Problem: after device uploads False, it still counted for 7 more
# seconds. This caused "antagal" — backend kept seeing motion for 7s
# after patient stopped moving.
#
# New approach: only the LATEST reading matters. If latest is False
# (or too old), device is not seizing. Period.
# Upload stagger (1.2s per device) is handled by UPLOAD_FRESHNESS_S=4s.
# =====================================================================
async def is_device_currently_seizing(device_id: str, now_utc: datetime) -> bool:
    freshness_cutoff = now_utc - timedelta(seconds=UPLOAD_FRESHNESS_S)
    latest = await database.fetch_one(
        sensor_data.select()
        .where(sensor_data.c.device_id == device_id)
        .order_by(sensor_data.c.timestamp.desc())
        .limit(1)
    )
    if not latest:
        return False
    # Must be recent AND True
    if latest["timestamp"] < freshness_cutoff:
        return False
    return bool(latest["seizure_flag"])

# =====================================================================
# get_motion_start_time()
#
# Walk backwards from now to find when this device's CURRENT continuous
# True bout actually started. Stop at the first gap > UPLOAD_FRESHNESS_S.
# Cap lookback to max threshold + buffer.
# =====================================================================
async def get_motion_start_time(device_id: str, now_utc: datetime) -> datetime:
    max_lookback = GTCS_THRESHOLD_1_DEVICE_SECONDS + 10  # 30s max
    lookback = now_utc - timedelta(seconds=max_lookback)
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
        if gap <= UPLOAD_FRESHNESS_S:
            earliest = rows[i]["timestamp"]
        else:
            break  # gap too large — this is where the bout started
    return earliest

# =====================================================================
# get_last_true_upload_time()
#
# Returns the timestamp of the most recent seizure_flag=True reading
# for any of the given devices. This is used as "motion_stop_time"
# when computing duration — it's the last moment we know motion existed.
# =====================================================================
async def get_last_true_upload_time(device_ids: list, now_utc: datetime) -> Optional[datetime]:
    lookback = now_utc - timedelta(seconds=GTCS_THRESHOLD_1_DEVICE_SECONDS + 30)
    latest_true = None
    for device_id in device_ids:
        row = await database.fetch_one(
            sensor_data.select()
            .where(sensor_data.c.device_id == device_id)
            .where(sensor_data.c.timestamp >= lookback)
            .where(sensor_data.c.seizure_flag == True)
            .order_by(sensor_data.c.timestamp.desc())
            .limit(1)
        )
        if row:
            if latest_true is None or row["timestamp"] > latest_true:
                latest_true = row["timestamp"]
    return latest_true


# =====================================================================
# APP
# =====================================================================
app = FastAPI(title="Seizure Monitor Backend v22")

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
        except Exception:
            print(f"[STARTUP] Column '{col_name}' already exists (ok)")

    # ----------------------------------------------------------------
    # CRITICAL: Close ALL open sessions on startup.
    #
    # When the server restarts, ALL in-memory state is lost:
    # - _device_motion_start is empty
    # - _gtcs_trigger_time is empty
    # Any open session in the DB has no corresponding in-memory state.
    # If left open, these ghost sessions cause false GTCS triggers
    # (the next True upload finds an open session and extends it,
    # or the fallback duration calculation gives absurd values like 71s).
    #
    # We delete open sessions instead of closing them because they were
    # never properly confirmed — the server died mid-session and we
    # don't know the true end time or duration.
    # ----------------------------------------------------------------
    print("[STARTUP] Clearing all open sessions (server restart)...")
    now_utc = datetime.now(timezone.utc)

    open_device = await database.fetch_all(
        device_seizure_sessions.select()
        .where(device_seizure_sessions.c.end_time == None)
    )
    for s in open_device:
        print(f"[STARTUP] Deleting open device session id={s['id']} device={s['device_id']}")
        await database.execute(
            device_seizure_sessions.delete()
            .where(device_seizure_sessions.c.id == s["id"])
        )

    open_user = await database.fetch_all(
        user_seizure_sessions.select()
        .where(user_seizure_sessions.c.end_time == None)
    )
    for s in open_user:
        print(f"[STARTUP] Deleting open {s['type']} session id={s['id']} user={s['user_id']}")
        await database.execute(
            user_seizure_sessions.delete()
            .where(user_seizure_sessions.c.id == s["id"])
        )

    print(f"[STARTUP] Cleared {len(open_device)} device + {len(open_user)} user open sessions.")

@app.on_event("shutdown")
async def shutdown():
    await database.disconnect()

@app.get("/api/health")
async def health():
    return {"status": "ok"}

@app.api_route("/", methods=["GET", "HEAD"])
async def root():
    return {"message": "Seizure Monitor Backend v22"}


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
# SEIZURE EVENT READ ENDPOINTS
# =====================================================================
def compute_duration(row) -> Optional[int]:
    # ALWAYS prefer the stored duration_seconds — it is computed from actual
    # motion time (trigger→stop), not wall clock (start→end).
    # The wall clock diff (end_time - start_time) includes pre-trigger motion
    # time and is ALWAYS larger than the true seizure duration.
    # Only fall back to wall clock if duration_seconds was never set (legacy rows).
    stored = row["duration_seconds"] if "duration_seconds" in row.keys() else None
    if stored is not None and stored > 0:
        return stored
    # Fallback for legacy rows only (no duration_seconds stored)
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
# ESP32 UPLOAD — /api/device/upload
#
# FLOW (no window, no grace period):
#
# 1. Save reading to DB.
# 2. For each device: check if its LATEST reading is True AND fresh.
#    → devices_currently_seizing = set of devices that are ACTIVE right now.
# 3. If active_count >= 1:
#    a. If no open GTCS: compute motion duration. If >= threshold → open GTCS.
#    b. If open GTCS: keep it open.
# 4. If active_count == 0 AND there is an open GTCS:
#    → Close GTCS NOW.
#    → Duration = trigger_time → last_true_upload_time (from DB).
#    → No grace. No window. Just close.
# =====================================================================
@app.post("/api/device/upload")
async def upload_device_data(payload: UnifiedESP32Payload):
    existing = await database.fetch_one(
        devices.select().where(devices.c.device_id == payload.device_id)
    )
    if not existing:
        raise HTTPException(status_code=404, detail=f"Device {payload.device_id} not registered")

    ts_utc = parse_esp32_timestamp(payload.timestamp_ms)
    # CRITICAL FIX: Use server arrival time (now_utc) for the DB timestamp,
    # NOT the ESP32 timestamp. The ESP32 clock can be behind the server clock
    # by several seconds, which causes is_device_currently_seizing() to think
    # a reading is "stale" the moment it arrives (ts_utc < freshness_cutoff).
    # Server arrival time is always "now" and always passes the freshness check.
    # We still keep ts_utc for logging only.
    server_arrival_time = datetime.now(timezone.utc)
    print(f"[UPLOAD] device={payload.device_id} | seizure={payload.seizure_flag} | ts={to_pht(ts_utc).strftime('%H:%M:%S PHT')} | arrived={to_pht(server_arrival_time).strftime('%H:%M:%S PHT')}")

    # Save to DB — use server_arrival_time so freshness checks work correctly
    await database.execute(sensor_data.insert().values(
        device_id=payload.device_id,
        timestamp=server_arrival_time,
        accel_x=payload.accel_x, accel_y=payload.accel_y, accel_z=payload.accel_z,
        gyro_x=payload.gyro_x, gyro_y=payload.gyro_y, gyro_z=payload.gyro_z,
        battery_percent=payload.battery_percent,
        seizure_flag=payload.seizure_flag
    ))
    await database.execute(device_data.insert().values(
        device_id=payload.device_id,
        timestamp=server_arrival_time,
        payload=json.dumps({
            "accel_x": payload.accel_x, "accel_y": payload.accel_y, "accel_z": payload.accel_z,
            "gyro_x": payload.gyro_x, "gyro_y": payload.gyro_y, "gyro_z": payload.gyro_z,
            "battery_percent": payload.battery_percent,
            "seizure_flag": payload.seizure_flag,
        })
    ))

    user_id = existing["user_id"]
    user_devices_rows = await database.fetch_all(
        devices.select().where(devices.c.user_id == user_id)
    )
    device_ids = [d["device_id"] for d in user_devices_rows]
    now_utc = server_arrival_time  # use same timestamp as what we saved to DB

    # Note: stale session cleanup is handled at startup.
    # We don't run it per-upload to avoid interfering with open sessions.

    # ----------------------------------------------------------------
    # Count devices CURRENTLY seizing (latest reading = True AND fresh)
    # No window. No stickiness. Just the most recent upload per device.
    # ----------------------------------------------------------------
    currently_seizing = []
    for did in device_ids:
        if await is_device_currently_seizing(did, now_utc):
            currently_seizing.append(did)

    devices_with_seizure = len(currently_seizing)
    print(f"[DETECTION] user={user_id} | seizing_now={devices_with_seizure}/{len(device_ids)} | devices={currently_seizing}")

    # ----------------------------------------------------------------
    # Update in-memory motion start time for this device.
    # True upload → record start if not set. False upload → clear it.
    # This is the key fix: motion duration accumulates across upload
    # cycles without being reset by timing gaps between device batches.
    # ----------------------------------------------------------------
    if payload.seizure_flag:
        if payload.device_id not in _device_motion_start:
            _device_motion_start[payload.device_id] = now_utc
            print(f"[MOTION] {payload.device_id} started at {to_pht(now_utc).strftime('%H:%M:%S')}")
    else:
        if payload.device_id in _device_motion_start:
            del _device_motion_start[payload.device_id]

    active_jerk = await get_active_user_seizure(user_id, "Jerk")
    active_gtcs = await get_active_user_seizure(user_id, "GTCS")

    # ================================================================
    # JERK PATH (requires all 3 devices spiking simultaneously)
    # ================================================================
    if active_jerk:
        jerk_age = (now_utc - active_jerk["start_time"]).total_seconds()

        if jerk_age >= JERK_TO_GTCS_ESCALATION_SECONDS and devices_with_seizure >= 1:
            print(f"[JERK→GTCS] ESCALATING (age={jerk_age:.1f}s)")
            await delete_jerk_events_near_time(user_id, active_jerk["start_time"])
            await database.execute(user_seizure_sessions.insert().values(
                user_id=user_id, type="GTCS",
                start_time=active_jerk["start_time"], end_time=None,
                seizing_devices=json.dumps(currently_seizing or device_ids)
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
            print(f"[JERK] Continuing (age={jerk_age:.1f}s)")
            return {"status": "saved", "event": "Jerk"}

    if devices_with_seizure >= 3 and not active_jerk and not active_gtcs:
        jerk_suppress = _jerk_suppress_until.get(user_id)
        if jerk_suppress and now_utc < jerk_suppress:
            print(f"[JERK] Suppressed for {(jerk_suppress - now_utc).total_seconds():.1f}s more")
        else:
            _jerk_suppress_until.pop(user_id, None)
            if not await get_recent_completed_gtcs(user_id, now_utc):
                # Use in-memory motion starts
                starts = [_device_motion_start[did] for did in currently_seizing if did in _device_motion_start]
                jerk_start = min(starts) if starts else now_utc
                print(f"[JERK] NEW SESSION start={to_pht(jerk_start).strftime('%H:%M:%S PHT')}")
                await database.execute(user_seizure_sessions.insert().values(
                    user_id=user_id, type="Jerk",
                    start_time=jerk_start, end_time=None,
                    seizing_devices=json.dumps(currently_seizing)
                ))
                return {"status": "saved", "event": "Jerk"}
            else:
                print(f"[JERK] Suppressed — recent GTCS exists")

    # ================================================================
    # GTCS PATH B — sustained motion from 1+ devices
    #
    # Uses IN-MEMORY motion start per device (_device_motion_start).
    # motion_start = when device first uploaded True this bout.
    # motion_duration = now - motion_start — accumulates correctly
    # across upload cycles, never reset by timing gaps.
    # ================================================================
    if devices_with_seizure >= 1:
        if active_gtcs:
            print(f"[GTCS] Continuing (id={active_gtcs['id']}, seizing={devices_with_seizure})")
            return {"status": "saved", "event": "GTCS"}

        gtcs_threshold = (GTCS_THRESHOLD_MULTI_DEVICE_SECONDS
                          if devices_with_seizure >= 2
                          else GTCS_THRESHOLD_1_DEVICE_SECONDS)

        # In-memory motion starts — reliable regardless of upload timing
        starts = [_device_motion_start[did] for did in currently_seizing if did in _device_motion_start]
        if not starts:
            # No in-memory record (server restarted?) — can't trigger yet
            print(f"[GTCS] No motion start recorded yet — waiting")
            return {"status": "saved", "event": "none"}

        motion_start = min(starts)
        motion_duration = (now_utc - motion_start).total_seconds()

        print(f"[GTCS] motion={motion_duration:.1f}s | threshold={gtcs_threshold}s | seizing={devices_with_seizure}")

        if motion_duration >= gtcs_threshold:
            print(f"[GTCS] *** TRIGGERED ***")
            _gtcs_trigger_time[user_id] = now_utc
            await database.execute(user_seizure_sessions.insert().values(
                user_id=user_id, type="GTCS",
                start_time=motion_start, end_time=None,
                seizing_devices=json.dumps(currently_seizing)
            ))
            return {"status": "saved", "event": "GTCS"}

        return {"status": "saved", "event": "none"}

    # ================================================================
    # devices_with_seizure == 0 — motion stopped
    # Close GTCS immediately. Duration = trigger → last True upload.
    # ================================================================
    if active_gtcs:
        last_true_time = await get_last_true_upload_time(device_ids, now_utc)
        trigger_time   = _gtcs_trigger_time.pop(user_id, None)

        if trigger_time and last_true_time and last_true_time > trigger_time:
            gtcs_duration = (last_true_time - trigger_time).total_seconds()
            end_time = last_true_time
            print(f"[GTCS] CLOSING — trigger={to_pht(trigger_time).strftime('%H:%M:%S')} → last_motion={to_pht(last_true_time).strftime('%H:%M:%S')} = {gtcs_duration:.1f}s")
        elif last_true_time and last_true_time > active_gtcs["start_time"]:
            gtcs_duration = (last_true_time - active_gtcs["start_time"]).total_seconds()
            end_time = last_true_time
            print(f"[GTCS] CLOSING (fallback) — duration={gtcs_duration:.1f}s")
        else:
            gtcs_duration = 0
            end_time = now_utc
            print(f"[GTCS] CLOSING (no True readings found)")

        gtcs_duration = max(0, gtcs_duration)

        if gtcs_duration >= MIN_GTCS_DURATION_SECONDS:
            await database.execute(
                user_seizure_sessions.update()
                .where(user_seizure_sessions.c.id == active_gtcs["id"])
                .values(end_time=end_time, duration_seconds=int(gtcs_duration))
            )
        else:
            print(f"[GTCS] Too short ({gtcs_duration:.1f}s) — deleting")
            await database.execute(
                user_seizure_sessions.delete()
                .where(user_seizure_sessions.c.id == active_gtcs["id"])
            )
        return {"status": "saved", "event": "none"}

    # Clean up stale in-memory state
    _gtcs_trigger_time.pop(user_id, None)
    return {"status": "saved", "event": "none"}


# =====================================================================
# ESP32 UPLOAD — /api/device/upload_seizure_event (SD queue flush)
#
# BUG 1 FIX: If any real-time session is currently OPEN → skip entirely.
# The real-time system is working; the SD event is either:
#   a) A duplicate of what PATH B already recorded, or
#   b) A stale event from a previous test/run
# Either way, we must NOT delete or replace the active session.
#
# Only write the SD event if:
#   1. No active session exists right now, AND
#   2. No duplicate session exists near the same start_time
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
        duration_sec = max(1, int((end_utc - start_utc).total_seconds()))
    if end_utc <= start_utc and duration_sec > 0:
        end_utc = start_utc + timedelta(seconds=duration_sec)

    print(f"[SD UPLOAD] user={user_id} type={payload.type} "
          f"start={to_pht(start_utc).strftime('%Y-%m-%d %H:%M:%S PHT')} dur={duration_sec}s")

    # ----------------------------------------------------------------
    # BUG 1 FIX: If a real-time session is currently open → skip.
    # Do NOT delete, do NOT replace. The real-time system is authoritative.
    # ----------------------------------------------------------------
    any_active = await get_any_active_user_seizure(user_id)
    if any_active:
        print(f"[SD UPLOAD] SKIPPED — active real-time session (id={any_active['id']}, type={any_active['type']}) is open")
        return {"status": "skipped", "reason": "active_realtime_session_open"}

    # ----------------------------------------------------------------
    # Duplicate check: same type + same start time (±30s)
    # ----------------------------------------------------------------
    tolerance = timedelta(seconds=30)
    existing = await database.fetch_one(
        user_seizure_sessions.select()
        .where(user_seizure_sessions.c.user_id == user_id)
        .where(user_seizure_sessions.c.type == payload.type)
        .where(user_seizure_sessions.c.start_time >= start_utc - tolerance)
        .where(user_seizure_sessions.c.start_time <= start_utc + tolerance)
    )
    if existing:
        print(f"[SD UPLOAD] Duplicate (id={existing['id']}) — skipping")
        return {"status": "duplicate", "event": payload.type}

    # ----------------------------------------------------------------
    # No active session, no duplicate → write the SD event
    # ----------------------------------------------------------------
    now_utc = datetime.now(timezone.utc)

    if payload.type == "GTCS":
        await delete_jerk_events_near_time(user_id, start_utc, tolerance_seconds=60)

    # Clear stale in-memory state
    _gtcs_trigger_time.pop(user_id, None)
    _jerk_suppress_until.pop(user_id, None)

    seizing_json = json.dumps(payload.seizing_devices or payload.device_ids)

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
            for sd_row in seizing_rows:
                if sd_row["device_id"] not in seen:
                    seen[sd_row["device_id"]] = True
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
    device_ids_list = [d["device_id"] for d in user_devices]
    query = sensor_data.select().where(
        and_(sensor_data.c.device_id.in_(device_ids_list), sensor_data.c.timestamp >= start_dt_utc)
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
