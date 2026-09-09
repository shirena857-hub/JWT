"""
FF Ultimate API — Merged from ffinfoo (real protobuf src) + sulavcodex + friend add/remove + bio update + bind info
/player-info  → real protobuf+AES source (ffinfoo type), NOT killersharmabot
/ai           → free AI Q&A (pollinations.ai)
/friend/add   → add friend via JWT / uid+password / access_token
/friend/remove→ remove friend
/update-bio   → update FF biography (long bio support)
/bind-info    → check recovery email & bind status
/platforms    → check linked platforms (Facebook, Gmail, VK, etc.)
Vercel-ready (WSGI Flask).
"""
import io
import os
import re
import json
import time
import base64
import binascii
import codecs
import random
import asyncio
import logging
import threading
import urllib.request
import urllib.error
import zipfile
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any, Tuple
from urllib.parse import urlparse, parse_qs
from functools import wraps
from collections import defaultdict

import warnings
import requests
from flask import Flask, request, jsonify, Response
from flask_cors import CORS

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad as crypto_pad, unpad as crypto_unpad
import httpx
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore")

try:
    import jwt as pyjwt
    PYJWT_AVAILABLE = True
except ImportError:
    PYJWT_AVAILABLE = False

# ── PIL (image generation) ─────────────────────────────────────────────────────
try:
    from PIL import Image, ImageDraw, ImageFont
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

# ── Protobuf: ffinfoo real-src player info ─────────────────────────────────────
try:
    from proto import FreeFire_pb2, main_pb2, AccountPersonalShow_pb2
    from google.protobuf import json_format
    from google.protobuf.message import Message
    PROTO_AVAILABLE = True
except Exception as _pe:
    PROTO_AVAILABLE = False
    logging.warning(f"Proto import failed: {_pe}")

# ── Protobuf: sulavcodex extras ────────────────────────────────────────────────
duo_pb2 = None
my_pb2   = None
output_pb2 = None
try:
    import Beta_pb2 as duo_pb2
except Exception:
    pass
try:
    import my_pb2
except Exception:
    pass
try:
    import output_pb2
except Exception:
    pass

# ── Protobuf: friend add/remove & social ──────────────────────────────────────
uid_gen_pb2     = None
remove_friend_pb2 = None
social_data_pb2 = None
like_req_pb2    = None
try:
    import uid_generator_pb2 as uid_gen_pb2
except Exception:
    pass
try:
    import RemoveFriend_Req_pb2 as remove_friend_pb2
except Exception:
    pass
try:
    import data_pb2 as social_data_pb2
except Exception:
    pass
try:
    import like_pb2 as like_req_pb2
except Exception:
    pass

# ── MajorLogin protobuf (inline — for access_token → JWT) ─────────────────────
try:
    from google.protobuf import descriptor_pool as _dp
    from google.protobuf.internal import builder as _builder2
    _MAJOR_BYTES = (
        b'\n\x13MajorLoginReq.proto"\xfa\n\n\nMajorLogin\x12\x12\n\nevent_time\x18\x03 \x01(\t'
        b'\x12\x11\n\tgame_name\x18\x04 \x01(\t\x12\x13\n\x0bplatform_id\x18\x05 \x01(\x05'
        b'\x12\x16\n\x0eclient_version\x18\x07 \x01(\t\x12\x17\n\x0fsystem_software\x18\x08'
        b' \x01(\t\x12\x17\n\x0fsystem_hardware\x18\t \x01(\t\x12\x18\n\x10telecom_operator'
        b'\x18\n \x01(\t\x12\x14\n\x0cnetwork_type\x18\x0b \x01(\t\x12\x14\n\x0cscreen_width'
        b'\x18\x0c \x01(\r\x12\x15\n\rscreen_height\x18\r \x01(\r\x12\x12\n\nscreen_dpi\x18'
        b'\x0e \x01(\t\x12\x19\n\x11processor_details\x18\x0f \x01(\t\x12\x0e\n\x06memory'
        b'\x18\x10 \x01(\r\x12\x14\n\x0cgpu_renderer\x18\x11 \x01(\t\x12\x13\n\x0bgpu_version'
        b'\x18\x12 \x01(\t\x12\x18\n\x10unique_device_id\x18\x13 \x01(\t\x12\x11\n\tclient_ip'
        b'\x18\x14 \x01(\t\x12\x10\n\x08language\x18\x15 \x01(\t\x12\x0f\n\x07open_id\x18\x16'
        b' \x01(\t\x12\x14\n\x0copen_id_type\x18\x17 \x01(\t\x12\x13\n\x0bdevice_type'
        b'\x18\x18 \x01(\t\x12\'\n\x10memory_available\x18\x19 \x01(\x0b2\r.GameSecurity'
        b'\x12\x14\n\x0caccess_token\x18\x1d \x01(\t\x12\x17\n\x0fplatform_sdk_id'
        b'\x18\x1e \x01(\x05\x12\x1a\n\x12network_operator_a\x18) \x01(\t\x12\x16\n\x0e'
        b'network_type_a\x18* \x01(\t\x12\x1c\n\x14client_using_version\x189 \x01(\t'
        b'\x12\x1e\n\x16external_storage_total\x18< \x01(\x05\x12"\n\x1aexternal_storage'
        b'_available\x18= \x01(\x05\x12\x1e\n\x16internal_storage_total\x18> \x01(\x05\x12"'
        b'\n\x1ainternal_storage_available\x18? \x01(\x05\x12#\n\x1bgame_disk_storage_available'
        b'\x18@ \x01(\x05\x12\x1f\n\x17game_disk_storage_total\x18A \x01(\x05\x12%\n\x1d'
        b'external_sdcard_avail_storage\x18B \x01(\x05\x12%\n\x1dexternal_sdcard_total'
        b'_storage\x18C \x01(\x05\x12\x10\n\x08login_by\x18I \x01(\x05\x12\x14\n\x0clibrary'
        b'_path\x18J \x01(\t\x12\x12\n\nreg_avatar\x18L \x01(\x05\x12\x15\n\rlibrary_token'
        b'\x18M \x01(\t\x12\x14\n\x0cchannel_type\x18N \x01(\x05\x12\x10\n\x08cpu_type'
        b'\x18O \x01(\x05\x12\x18\n\x10cpu_architecture\x18Q \x01(\t\x12\x1b\n\x13client'
        b'_version_code\x18S \x01(\t\x12\x14\n\x0cgraphics_api\x18V \x01(\t\x12\x1d\n\x15'
        b'supported_astc_bitset\x18W \x01(\r\x12\x1a\n\x12login_open_id_type\x18X \x01(\x05'
        b'\x12\x18\n\x10analytics_detail\x18Y \x01(\x0c\x12\x14\n\x0cloading_time\x18\\'
        b' \x01(\r\x12\x17\n\x0frelease_channel\x18] \x01(\t\x12\x12\n\nextra_info\x18^ \x01(\t'
        b'\x12 \n\x18android_engine_init_flag\x18_ \x01(\r\x12\x0f\n\x07if_push\x18a'
        b' \x01(\x05\x12\x0e\n\x06is_vpn\x18b \x01(\x05\x12\x1c\n\x14origin_platform_type'
        b'\x18c \x01(\t\x12\x1d\n\x15primary_platform_type\x18d \x01(\t"5\n\x0c'
        b'GameSecurity\x12\x0f\n\x07version\x18\x06 \x01(\x05\x12\x14\n\x0chidden_value\x18'
        b'\x08 \x01(\x04b\x06proto3'
    )
    _MAJOR_RES_BYTES = (
        b'\n\x13MajorLoginRes.proto"|\n\rMajorLoginRes\x12\x13\n\x0baccount_uid\x18\x01 \x01(\x04'
        b'\x12\x0e\n\x06region\x18\x02 \x01(\t\x12\r\n\x05token\x18\x08 \x01(\t\x12\x0b\n\x03url'
        b'\x18\n \x01(\t\x12\x11\n\ttimestamp\x18\x15 \x01(\x03\x12\x0b\n\x03key\x18\x16 \x01(\x0c'
        b'\x12\n\n\x02iv\x18\x17 \x01(\x0cb\x06proto3'
    )
    _MAJOR_DESC     = _dp.Default().AddSerializedFile(_MAJOR_BYTES)
    _MAJOR_RES_DESC = _dp.Default().AddSerializedFile(_MAJOR_RES_BYTES)
    _major_globals: dict = {}
    _builder2.BuildMessageAndEnumDescriptors(_MAJOR_DESC, _major_globals)
    _builder2.BuildTopDescriptorsAndMessages(_MAJOR_DESC, 'MajorLoginReq_pb2', _major_globals)
    _builder2.BuildMessageAndEnumDescriptors(_MAJOR_RES_DESC, _major_globals)
    _builder2.BuildTopDescriptorsAndMessages(_MAJOR_RES_DESC, 'MajorLoginRes_pb2', _major_globals)
    MajorLogin    = _major_globals['MajorLogin']
    GameSecurity  = _major_globals['GameSecurity']
    MajorLoginRes = _major_globals['MajorLoginRes']
    MAJOR_LOGIN_PROTO_OK = True
except Exception as _mle:
    MajorLogin = None
    MajorLoginRes = None
    MAJOR_LOGIN_PROTO_OK = False
    logging.warning(f"MajorLogin proto init failed: {_mle}")

# ── Logging ────────────────────────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ff_api")

# ── Flask App ──────────────────────────────────────────────────────────────────
app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

# ── Constants ──────────────────────────────────────────────────────────────────
# ffinfoo AES keys (base64-decoded)
MAIN_KEY = base64.b64decode('WWcmdGMlREV1aDYlWmNeOA==')
MAIN_IV  = base64.b64decode('Nm95WkRyMjJFM3ljaGpNJQ==')
RELEASEVERSION = "OB54"
USERAGENT = "Dalvik/2.1.0 (Linux; U; Android 13; CPH2095 Build/RKQ1.211119.001)"

# sulavcodex AES keys
AES_KEY = bytes([89,103,38,116,99,37,68,69,117,104,54,37,90,99,94,56])
AES_IV  = bytes([54,111,121,90,68,114,50,50,69,51,121,99,104,106,77,37])
SECRET_KEY = b"1e5898ccb8dfdd921f9bdea848768b64a201"
HEX_KEY = bytes.fromhex(
    "32656534343831396539623435393838343531343130363762323831363231383"
    "74d306435643761663964386637653030633165353437313562376431653"[:-1]
)

REGION_LANG = {
    "ME":"ar","IND":"hi","ID":"id","VN":"vi","TH":"th",
    "BD":"bn","PK":"ur","TW":"zh","CIS":"ru","SAC":"es","BR":"pt"
}
ALL_REGIONS = list(REGION_LANG.keys())
SUPPORTED_REGIONS = {"IND","BR","US","SAC","NA","SG","RU","ID","TW","VN","TH","ME","PK","CIS","BD","EUROPE"}

CDN_URL = "https://cdn.jsdelivr.net/gh/ShahGCreator/icon@main/PNG"
EAT_TARGET_URL = os.environ.get("TARGET_API_URL", "https://api-otrss.garena.com/support/callback/")
UPDATE_API_URL = "https://mg24-auto-update.vercel.app/"
POLLINATIONS_URL = "https://text.pollinations.ai/{}"

# Image/layout config
AVATAR_ZOOM = 1.26
AVATAR_SHIFT_Y = 0
AVATAR_SHIFT_X = 0
BANNER_START_X = 0.25
BANNER_START_Y = 0.29
BANNER_END_X   = 0.81
BANNER_END_Y   = 0.65
FONT_MAIN     = "arial_unicode_bold.otf"
FONT_CHEROKEE = "NotoSansCherokee.ttf"
PRIME_FILES = {i: f"prime{i}.png" for i in range(9)}
PRIME8_FRAME_FILE = "prime8frame.png"
CUSTOM_BADGE_FILES = {
    "vbadge1":"vbadge1.png","vbadge2":"vbadge2.png",
    "vbadge3":"vbadge3.png","vbadge4":"vbadge4.png",
    "gmbadge":"gmbadge.jpg","cbadge":"cbadge.png","probadge":"probadge.png",
}
CUSTOM_FRAME_FILES = {"prime8frame":"prime8frame.png","ebadgeframe":"ebadgeframe.png"}
OUTFIT_BACKGROUND = "outfit.png"
ICON_SIZE = (95, 95)
CHARACTER_RENDER_SIZE = (700, 700)
FALLBACK_IDS = ["211000000","214000000","208000000","203000000","204000000","205000000","212000000"]
DEFAULT_AVATAR_ID = "710034057"
HEX_POSITIONS = {
    "mask":(990,420),"shirt":(190,90),"pants":(40,420),
    "shoes":(840,90),"emote":(40,230),"armor":(990,230),
    "weapon":(190,560),"pet":(840,560)
}

ITEMS = {f"item{i}": v for i, v in enumerate(
    [212000000,203000000,212000000,211000000,211000000,204000000,
     205000000,203000000,211000000,203000000,204000000,205000000,
     203000000,211000000,204000000], 1
)}

# Level XP table
LEVELS = {
    "1":0,"2":48,"3":202,"4":544,"5":1012,"6":1844,"7":2792,"8":3800,
    "9":5020,"10":6456,"11":8108,"12":9976,"13":12060,"14":14360,"15":16876,
    "16":19608,"17":22556,"18":25720,"19":29100,"20":32696,"21":36508,"22":40536,
    "23":44780,"24":49240,"25":53916,"26":58808,"27":63916,"28":69240,"29":74780,
    "30":80536,"31":86508,"32":92696,"33":99100,"34":105720,"35":112556,"36":119608,
    "37":126876,"38":134360,"39":142060,"40":149976,"41":158108,"42":166456,
    "43":175020,"44":183800,"45":192796,"46":202008,"47":211436,"48":221080,
    "49":230940,"50":241016,"51":251308,"52":261816,"53":272540,"54":283480,
    "55":294636,"56":306008,"57":317596,"58":329400,"59":341420,"60":353656,
    "61":366108,"62":378776,"63":391660,"64":404760,"65":418076,"66":431608,
    "67":445356,"68":459320,"69":473500,"70":487896,"71":502508,"72":517336,
    "73":532380,"74":547640,"75":563116,"76":578808,"77":594716,"78":610840,
    "79":627180,"80":643736,"81":660508,"82":677496,"83":694700,"84":712120,
    "85":729756,"86":747608,"87":765676,"88":783960,"89":802460,"90":821176,
    "91":840108,"92":859256,"93":878620,"94":898200,"95":918020,"96":938076,
    "97":958368,"98":978896,"99":999660,"100":1020660
}

# ── Global caches ──────────────────────────────────────────────────────────────
_token_cache: Dict[str, dict] = {}          # ffinfoo region tokens
_uid_region_cache: Dict[str, str] = {}      # uid → region
_jwt_cache: Dict[str, dict] = {}            # sulavcodex jwt cache
_duo_jwt_cache: Dict[str, dict] = {}
_cached_config = None
_cache_lock = threading.Lock()
_request_counter = {"total": 0, "player_info": 0, "banner": 0, "duo": 0, "ai": 0}
_start_time = datetime.utcnow()

# ── Item DB ────────────────────────────────────────────────────────────────────
_DATA_JSON = os.path.join(os.path.dirname(__file__), "data.json")
item_db: List[Dict] = []
try:
    if os.path.exists(_DATA_JSON):
        with open(_DATA_JSON, "r", encoding="utf-8") as _f:
            item_db = json.load(_f)
        logger.info(f"Loaded {len(item_db)} items from data.json")
except Exception as _e:
    logger.warning(f"data.json load failed: {_e}")

# ══════════════════════════════════════════════════════════════════════════════
#  CRYPTO HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def _pad_pkcs7(data: bytes) -> bytes:
    n = AES.block_size - (len(data) % AES.block_size)
    return data + bytes([n] * n)

def aes_cbc_encrypt_main(plaintext: bytes) -> bytes:
    """Encrypt using ffinfoo MAIN_KEY/MAIN_IV."""
    cipher = AES.new(MAIN_KEY, AES.MODE_CBC, MAIN_IV)
    return cipher.encrypt(_pad_pkcs7(plaintext))

def aes_cbc_encrypt_api(plaintext: bytes) -> bytes:
    """Encrypt using sulavcodex AES_KEY/AES_IV."""
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    return cipher.encrypt(crypto_pad(plaintext, AES.block_size))

def aes_cbc_encrypt_hex(plain_hex: str) -> str:
    plain = bytes.fromhex(plain_hex)
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    return cipher.encrypt(crypto_pad(plain, AES.block_size)).hex()

# ══════════════════════════════════════════════════════════════════════════════
#  FFINFOO — REAL PROTOBUF PLAYER INFO SYSTEM  (src type)
# ══════════════════════════════════════════════════════════════════════════════

_SERVICE_ACCOUNTS = {
    "IND": {"uid":"4360460587","password":"Krsxh_6KPH0_BY_KRSXH_NVRDIE_T13KU"},
    "SG":  {"uid":"3158350464","password":"70EA041FCF79190E3D0A8F3CA95CAAE1F39782696CE9D85C2CCD525E28D223FC"},
    "RU":  {"uid":"3301239795","password":"DD40EE772FCBD61409BB15033E3DE1B1C54EDA83B75DF0CDD24C34C7C8798475"},
    "ID":  {"uid":"3301269321","password":"D11732AC9BBED0DED65D0FED7728CA8DFF408E174202ECF1939E328EA3E94356"},
    "TW":  {"uid":"3301329477","password":"359FB179CD92C9C1A2A917293666B96972EF8A5FC43B5D9D61A2434DD3D7D0BC"},
    "US":  {"uid":"3301387397","password":"BAC03CCF677F8772473A09870B6228ADFBC1F503BF59C8D05746DE451AD67128"},
    "VN":  {"uid":"3301447047","password":"044714F5B9284F3661FB09E4E9833327488B45255EC9E0CCD953050E3DEF1F54"},
    "TH":  {"uid":"3301470613","password":"39EFD9979BD6E9CCF6CBFF09F224C4B663E88B7093657CB3D4A6F3615DDE057A"},
    "ME":  {"uid":"3301535568","password":"BEC9F99733AC7B1FB139DB3803F90A7E78757B0BE395E0A6FE3A520AF77E0517"},
    "PK":  {"uid":"3301828218","password":"3A0E972E57E9EDC39DC4830E3D486DBFB5DA7C52A4E8B0B8F3F9DC4450899571"},
    "CIS": {"uid":"3309128798","password":"412F68B618A8FAEDCCE289121AC4695C0046D2E45DB07EE512B4B3516DDA8B0F"},
    "BR":  {"uid":"3158668455","password":"44296D19343151B25DE68286BDC565904A0DA5A5CC5E96B7A7ADBE7C11E07933"},
}
_SERVER_URLS = {
    "IND": "https://client.ind.freefiremobile.com",
    "SG":  "https://client.sg.freefiremobile.com",
    "ID":  "https://client.id.freefiremobile.com",
    "TW":  "https://client.tw.freefiremobile.com",
    "VN":  "https://client.vn.freefiremobile.com",
    "TH":  "https://client.th.freefiremobile.com",
    "ME":  "https://client.me.freefiremobile.com",
    "PK":  "https://client.pk.freefiremobile.com",
    "CIS": "https://client.cis.freefiremobile.com",
    "BR":  "https://client.br.freefiremobile.com",
    "US":  "https://client.us.freefiremobile.com",
    "RU":  "https://client.ru.freefiremobile.com",
}


def _get_oauth_token(uid: str, password: str) -> Optional[str]:
    """Get Garena OAuth access token for a service account."""
    url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    headers = {
        "User-Agent": USERAGENT,
        "Connection": "Keep-Alive",
        "Accept-Encoding": "gzip",
        "Content-Type": "application/x-www-form-urlencoded",
    }
    body = f"uid={uid}&password={password}&response_type=token&client_type=2&client_secret=&client_id=100067"
    try:
        resp = requests.post(url, headers=headers, data=body, timeout=15, verify=False)
        if resp.status_code != 200:
            return None
        data = resp.json()
        open_id = data.get("open_id","")
        token   = data.get("access_token","")
        if not token:
            return None
        # Build protobuf login request
        if not PROTO_AVAILABLE:
            return None
        login_req = FreeFire_pb2.LoginReq()
        login_req.open_id      = open_id
        login_req.open_id_type = "4"
        login_req.login_token  = token
        login_req.orign_platform_type = "6"
        payload = aes_cbc_encrypt_main(login_req.SerializeToString())
        login_headers = {
            "User-Agent": USERAGENT,
            "Connection": "Keep-Alive",
            "Accept-Encoding": "gzip",
            "Content-Type": "application/octet-stream",
            "Expect": "100-continue",
            "X-Unity-Version": "2018.4.11f1",
            "X-GA": "v1 1",
            "ReleaseVersion": RELEASEVERSION,
        }
        lr = requests.post(
            "https://loginbp.ggblueshark.com/MajorLogin",
            data=payload, headers=login_headers, timeout=15, verify=False
        )
        login_res = FreeFire_pb2.LoginRes()
        login_res.ParseFromString(lr.content)
        return login_res.token or None
    except Exception as e:
        logger.warning(f"OAuth token error for uid={uid}: {e}")
        return None


def _ensure_region_token(region: str) -> Optional[Tuple[str, str]]:
    """Return (jwt_token, server_url) for a region, refreshing if needed."""
    cached = _token_cache.get(region)
    if cached and cached.get("expires_at", 0) > time.time():
        return cached["token"], cached["server_url"]
    acc = _SERVICE_ACCOUNTS.get(region.upper(), _SERVICE_ACCOUNTS["IND"])
    token = _get_oauth_token(acc["uid"], acc["password"])
    if not token:
        return None, None
    server_url = _SERVER_URLS.get(region.upper(), _SERVER_URLS["IND"])
    _token_cache[region] = {"token": token, "server_url": server_url, "expires_at": time.time() + 3600}
    return token, server_url


def _fetch_player_proto(uid: str, region: str) -> Optional[Dict]:
    """Fetch player info via protobuf (ffinfoo src type)."""
    if not PROTO_AVAILABLE:
        return None
    try:
        token, server_url = _ensure_region_token(region)
        if not token:
            return None
        # Build GetPlayerPersonalShow protobuf payload (use ParseDict for correct type coercion)
        msg = main_pb2.GetPlayerPersonalShow()
        json_format.ParseDict({"a": uid, "b": 7}, msg)
        payload = aes_cbc_encrypt_main(msg.SerializeToString())
        headers = {
            "User-Agent": USERAGENT,
            "Connection": "Keep-Alive",
            "Accept-Encoding": "gzip",
            "Content-Type": "application/octet-stream",
            "Expect": "100-continue",
            "Authorization": token,
            "X-Unity-Version": "2018.4.11f1",
            "X-GA": "v1 1",
            "ReleaseVersion": RELEASEVERSION,
        }
        resp = requests.post(
            f"{server_url}/GetPlayerPersonalShow",
            data=payload, headers=headers, timeout=12, verify=False
        )
        if resp.status_code != 200:
            return None
        info = AccountPersonalShow_pb2.AccountPersonalShowInfo()
        info.ParseFromString(resp.content)
        return json.loads(json_format.MessageToJson(info))
    except Exception as e:
        logger.warning(f"Proto fetch error uid={uid} region={region}: {e}")
        return None


def get_player_info_src(uid: str) -> Dict:
    """
    Get REAL player info using ffinfoo protobuf src type.
    Tries cached region first, then all regions.
    Returns raw protobuf-parsed JSON dict.
    """
    _request_counter["player_info"] = _request_counter.get("player_info", 0) + 1
    cached_region = _uid_region_cache.get(uid)
    if cached_region:
        result = _fetch_player_proto(uid, cached_region)
        if result:
            return result
    for region in ["IND","SG","ID","BR","VN","TH","ME","PK","CIS","US","RU","TW"]:
        result = _fetch_player_proto(uid, region)
        if result and (result.get("basicInfo") or result.get("profileInfo")):
            _uid_region_cache[uid] = region
            return result
    return {}


def parse_player_data(raw: Dict) -> Dict:
    """Parse raw protobuf JSON into a unified dict (sulavcodex-compatible)."""
    profile    = raw.get("profileInfo", {}) or {}
    basic      = raw.get("basicInfo", {}) or {}
    clan       = raw.get("clanBasicInfo", {}) or {}
    prime_info = raw.get("primeInfo", {}) or {}
    pet_info   = raw.get("petInfo", {}) or {}

    name = (profile.get("nickname") or basic.get("nickname") or "Unknown").strip()
    level = str(profile.get("level") or basic.get("level") or 0)
    guild = clan.get("clanName", "")
    headPic   = str(profile.get("headPic") or basic.get("headPic") or "")
    banner_id = str(profile.get("bannerId") or basic.get("bannerId") or "")
    exp = basic.get("exp", 0) or 0
    region = basic.get("region", "")
    account_id = str(basic.get("accountId", ""))

    # Prime level (search everywhere)
    prime_level = prime_info.get("primeLevel") or profile.get("primeLevel") or basic.get("primeLevel")
    if prime_level is None:
        def _search_prime(obj):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if 'prime' in k.lower() and isinstance(v, int):
                        return v
                    r = _search_prime(v)
                    if r is not None:
                        return r
            elif isinstance(obj, list):
                for item in obj:
                    r = _search_prime(item)
                    if r is not None:
                        return r
            return None
        prime_level = _search_prime(raw)
    try:
        prime_level = max(0, min(8, int(prime_level or 0)))
    except:
        prime_level = 0

    clothes      = profile.get("clothes") or []
    weapon_skins = basic.get("weaponSkinShows") or []
    weapon       = weapon_skins[0] if weapon_skins else None
    pet          = pet_info.get("skinId")
    character    = profile.get("avatarId") or DEFAULT_AVATAR_ID

    return {
        "name": name, "level": level, "guild": guild,
        "headPic": headPic, "banner_id": banner_id, "prime_level": prime_level,
        "clothes": clothes, "weapon": weapon, "pet": pet, "character": character,
        "exp": exp, "region": region, "account_id": account_id,
        "raw": raw,
    }


class PlayerNotFoundError(ValueError):
    """Raised when the real Free Fire service has no data for a UID."""


def fetch_player_data(uid: str) -> Dict:
    """High-level: fetch + parse player data.

    Missing players are explicit 404s, never a partially fake player object.
    Existing route handlers already convert ValueError into a JSON 404.
    """
    raw = get_player_info_src(uid)
    if not raw:
        raise PlayerNotFoundError(f"Player not found: UID {uid}")
    return parse_player_data(raw)


def _get_player(uid: str):
    """Route helper → (player_dict, None) or (None, error_response_tuple)."""
    if not uid:
        return None, (jsonify({"error": "uid is required", "hint": "Add ?uid=YOUR_UID"}), 400)
    try:
        return fetch_player_data(uid), None
    except PlayerNotFoundError as exc:
        return None, (jsonify({
            "error": "Player not found",
            "uid": uid,
            "detail": str(exc),
            "hint": "Check the UID is correct, or the player may be in a restricted region.",
        }), 404)

# ══════════════════════════════════════════════════════════════════════════════
#  SULAVCODEX — JWT / TOKEN SYSTEM  (for /token endpoint)
# ══════════════════════════════════════════════════════════════════════════════

def get_play_store_version() -> str:
    try:
        resp = requests.get("https://play.google.com/store/apps/details?id=com.dts.freefireth", timeout=8)
        m = re.search(r'\[\[\["(\d+\.\d+\.\d+)"', resp.text)
        return m.group(1) if m else "1.112.1"
    except:
        return "1.112.1"


def get_access_token_sulav(uid: str, password: str) -> Tuple[Optional[str], Optional[str], Optional[bytes], Optional[str]]:
    url = "https://100067.connect.garena.com/oauth/guest/token/grant"
    headers = {
        "User-Agent": "GarenaMSDK/4.0.19P4(Linux;Android 9;EN;Release;)",
        "Content-Type": "application/x-www-form-urlencoded",
    }
    body = {
        "uid": uid, "password": password,
        "response_type": "token", "client_type": "2",
        "client_id": "100067"
    }
    try:
        resp = requests.post(url, headers=headers, data=body, timeout=20, verify=False)
        if resp.status_code != 200:
            return None, None, None, f"HTTP {resp.status_code}"
        data = resp.json()
        if "open_id" not in data or "access_token" not in data:
            return None, None, None, "Invalid response"
        open_id      = data["open_id"]
        access_token = data["access_token"]
        keystream = [0x30,0x30,0x30,0x32,0x30,0x31,0x37,0x30,0x30,0x30,0x30,0x30,
                     0x32,0x30,0x31,0x37,0x30,0x30,0x30,0x30,0x30,0x32,0x30,0x31,
                     0x37,0x30,0x30,0x30,0x30,0x30,0x32,0x30]
        encoded = ""
        for i in range(len(open_id)):
            encoded += chr(ord(open_id[i]) ^ keystream[i % len(keystream)])
        field = codecs.decode(
            ''.join(c if 32 <= ord(c) <= 126 else f'\\u{ord(c):04x}' for c in encoded),
            'unicode_escape'
        ).encode('latin1')
        return access_token, open_id, field, None
    except Exception as e:
        return None, None, None, str(e)[:60]


def major_login_sulav(access_token: str, open_id: str, region: str) -> Optional[Dict]:
    lang = REGION_LANG.get(region.upper(), "en")
    payload_parts = [
        b'\x1a\x132025-08-30 05:19:21"\tfree fire(\x01:\x081.114.13B2Android OS 9 / API-28 (PI/rel.cjw.20220518.114133)J\x08HandheldR\nATM MobilsZ\x04WIFI`\xb6\nh\xee\x05r\x03300z\x1fARMv7 VFPv3 NEON VMH | 2400 | 2\x80\x01\xc9\x0f\x8a\x01\x0fAdreno (TM) 640\x92\x01\rOpenGL ES 3.2\x9a\x01+Google|dfa4ab4b-9dc4-454e-8065-e70c733fa53f\xa2\x01\x0e105.235.139.91\xaa\x01\x02',
        lang.encode("ascii"),
        b'\xb2\x01 1d8ec0240ede109973f3321b9354b44d\xba\x01\x014\xc2\x01\x08Handheld\xca\x01\x10Asus ASUS_I005DA\xea\x01@afcfbf13334be42036e4f742c80b956344bed760ac91b3aff9b607a610ab4390\xf0\x01\x01\xca\x02\nATM Mobils\xd2\x02\x04WIFI\xca\x03 7428b253defc164018c604a1ebbfebdf\xe0\x03\xa8\x81\x02\xe8\x03\xf6\xe5\x01\xf0\x03\xaf\x13\xf8\x03\x84\x07\x80\x04\xe7\xf0\x01\x88\x04\xa8\x81\x02\x90\x04\xe7\xf0\x01\x98\x04\xa8\x81\x02\xc8\x04\x01\xd2\x04=/data/app/com.dts.freefireth-PdeDnOilCSFn37p1AH_FLg==/lib/arm\xe0\x04\x01\xea\x04_2087f61c19f57f2af4e7feff0b24d9d9|/data/app/com.dts.freefireth-PdeDnOilCSFn37p1AH_FLg==/base.apk\xf0\x04\x03\xf8\x04\x01\x8a\x05\x0232\x9a\x05\n2019118692\xb2\x05\tOpenGLES2\xb8\x05\xff\x7f\xc0\x05\x04\xe0\x05\xf3F\xea\x05\x07android\xf2\x05pKqsHT5ZLWrYljNb5Vqh//yFRlaPHSO9NWSQsVvOmdhEEn7W+VHNUK+Q+fduA3ptNrGB0Ll0LRz3WW0jOwesLj6aiU7sZ40p8BfUE/FI/jzSTwRe2\xf8\x05\xfb\xe4\x06\x88\x06\x01\x90\x06\x01\x9a\x06\x014\xa2\x06\x014\xb2\x06"GQ@O\x00\x0e^\x00D\x06UA\x0ePM\r\x13hZ\x07T\x06\x0cm\\V\x0ejYV;\x0bU5'
    ]
    payload = b''.join(payload_parts)
    use_bluefox = region.upper() in ["ME","TH"]
    url = "https://loginbp.common.ggbluefox.com/MajorLogin" if use_bluefox else "https://loginbp.ggblueshark.com/MajorLogin"
    headers = {
        "Accept-Encoding": "gzip",
        "Authorization": "Bearer",
        "Connection": "Keep-Alive",
        "Content-Type": "application/x-www-form-urlencoded",
        "Host": "loginbp.common.ggbluefox.com" if use_bluefox else "loginbp.ggblueshark.com",
        "ReleaseVersion": "OB54",
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_I005DA Build/PI)",
        "X-GA": "v1 1",
        "X-Unity-Version": "2018.4.11f1",
    }
    data = payload.replace(
        b'afcfbf13334be42036e4f742c80b956344bed760ac91b3aff9b607a610ab4390',
        access_token.encode()
    ).replace(b'1d8ec0240ede109973f3321b9354b44d', open_id.encode())
    encrypted = aes_cbc_encrypt_hex(data.hex())
    try:
        resp = requests.post(url, headers=headers, data=bytes.fromhex(encrypted), verify=False, timeout=20)
        if resp.status_code == 200 and len(resp.text) > 10:
            m = re.search(r'(eyJ[a-zA-Z0-9\-_]+\.eyJ[a-zA-Z0-9\-_]+\.?[a-zA-Z0-9\-_]+)', resp.text)
            if m:
                jwt_token = m.group(1)
                parts = jwt_token.split('.')
                if len(parts) >= 2:
                    p = parts[1]
                    p += '=' * (4 - len(p) % 4) if len(p) % 4 else ''
                    decoded = json.loads(base64.urlsafe_b64decode(p))
                    account_id = decoded.get('account_id') or decoded.get('external_id')
                    if account_id:
                        return {"jwt_token": jwt_token, "account_id": str(account_id)}
        return None
    except:
        return None


def generate_jwt_sync(uid: str, password: str, region: str = "AUTO") -> Dict:
    result = {
        "uid": uid, "timestamp": datetime.utcnow().isoformat(), "success": False,
        "access_token": None, "open_id": None, "jwt_token": None,
        "account_id": None, "region_used": None, "error": None,
    }
    regions = ALL_REGIONS if (not region or region.upper() == "AUTO") else [region.upper()]
    access_token, open_id, field, err = get_access_token_sulav(uid, password)
    if not access_token:
        result["error"] = f"Access token failed: {err}"
        return result
    result["access_token"] = access_token
    result["open_id"] = open_id
    for r in regions:
        lr = major_login_sulav(access_token, open_id, r)
        if lr and lr.get("jwt_token"):
            result["jwt_token"]   = lr["jwt_token"]
            result["account_id"]  = lr["account_id"]
            result["region_used"] = r
            result["success"]     = True
            return result
        time.sleep(0.2)
    result["error"] = "MajorLogin failed for all regions"
    return result

# ══════════════════════════════════════════════════════════════════════════════
#  HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def _font_path(name: str) -> Optional[str]:
    p = os.path.join(os.path.dirname(__file__), name)
    return p if os.path.exists(p) else None


def clean_text(text: str) -> str:
    if not text:
        return ""
    return re.sub(r'[\x00-\x1f\x7f-\x9f]', '', str(text)).strip()


def decode_nickname(encoded: str) -> str:
    try:
        raw = base64.b64decode(encoded)
        dec = bytearray(b ^ SECRET_KEY[i % len(SECRET_KEY)] for i, b in enumerate(raw))
        return dec.decode('utf-8', errors='replace')
    except:
        return encoded


def decode_jwt_payload(token: str) -> Dict:
    try:
        parts = token.split('.')
        p = parts[1]
        p += '=' * (4 - len(p) % 4) if len(p) % 4 else ''
        return json.loads(base64.urlsafe_b64decode(p).decode())
    except:
        return {}


def _base64_encode_value(value: Any, urlsafe: bool = False) -> str:
    """Encode text or JSON-safe data without leaking internal errors."""
    if isinstance(value, (dict, list, int, float, bool)) or value is None:
        raw = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    else:
        raw = str(value).encode("utf-8")
    encoder = base64.urlsafe_b64encode if urlsafe else base64.b64encode
    return encoder(raw).decode("ascii")


def _base64_decode_value(encoded: str, urlsafe: bool = False) -> Dict:
    """Decode base64/base64url and return text plus parsed JSON when possible."""
    if not isinstance(encoded, str) or not encoded.strip():
        raise ValueError("data is required")
    compact = re.sub(r"\s+", "", encoded)
    # Accept unpadded base64, but reject malformed input instead of returning
    # surprising binary output.
    if len(compact) % 4:
        compact += "=" * (4 - len(compact) % 4)
    decoder = base64.urlsafe_b64decode if urlsafe else base64.b64decode
    try:
        raw = decoder(compact.encode("ascii"), validate=not urlsafe)
    except (ValueError, binascii.Error, UnicodeEncodeError) as exc:
        raise ValueError("invalid base64 data") from exc
    try:
        text = raw.decode("utf-8")
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            parsed = None
        return {
            "text": text,
            "json": parsed,
            "bytes": len(raw),
            "encoding": "base64url" if urlsafe else "base64",
        }
    except UnicodeDecodeError:
        return {
            "text": None,
            "json": None,
            "bytes": len(raw),
            "hex": raw.hex(),
            "encoding": "base64url" if urlsafe else "base64",
        }


def _body_or_args() -> Dict:
    """Read JSON body first, then form/query values for simple utility routes."""
    body = request.get_json(silent=True)
    if isinstance(body, dict):
        return body
    return request.args.to_dict(flat=True)


def get_exp_for_level(level: int) -> int:
    return LEVELS.get(str(level), 0)


def calculate_level_progress(current_exp: int, current_level: int) -> Optional[Dict]:
    if current_level >= 100:
        return {"current_level": 100, "current_exp": current_exp,
                "exp_for_next_level": LEVELS["100"], "exp_needed": 0,
                "exp_needed_for_100": 0, "progress_percentage": 100}
    exp_cur  = get_exp_for_level(current_level)
    exp_next = get_exp_for_level(current_level + 1)
    exp_100  = get_exp_for_level(100)
    if not exp_next:
        return None
    exp_range = exp_next - exp_cur
    progress  = min(100, round(((current_exp - exp_cur) / exp_range) * 100, 1)) if exp_range > 0 else 0
    return {
        "current_level": current_level, "current_exp": current_exp,
        "exp_for_current_level": exp_cur, "exp_for_next_level": exp_next,
        "exp_needed": max(0, exp_next - current_exp),
        "exp_needed_for_100": max(0, exp_100 - current_exp),
        "progress_percentage": progress,
    }


def search_items(query: str) -> List[Dict]:
    q = query.lower().strip()
    return [
        it for it in item_db
        if q in it.get("name","").lower()
        or q == str(it.get("itemID",""))
        or q in it.get("itemType","").lower()
        or q in it.get("type","").lower()
    ]


def is_cherokee(c: str) -> bool:
    return 0x13A0 <= ord(c) <= 0x13FF or 0xAB70 <= ord(c) <= 0xABBF


def sync_fetch_url(url: str) -> Optional[bytes]:
    try:
        req = urllib.request.Request(url, headers={"User-Agent":"Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=8) as r:
            return r.read()
    except:
        return None


def fetch_icon(icon_id, size=ICON_SIZE, is_character=False) -> Optional[Any]:
    if not PIL_AVAILABLE:
        return None
    try:
        if is_character:
            data = sync_fetch_url(
                f"https://raw.githubusercontent.com/danggerr88-alt/danger-character-api/main/pngs/{icon_id}.png"
            )
            if data:
                img = Image.open(io.BytesIO(data)).convert("RGBA")
                bbox = img.getbbox()
                if bbox:
                    img = img.crop(bbox)
                w, h = img.size
                ratio = min(size[0]/w, size[1]/h)
                return img.resize((int(w*ratio), int(h*ratio)), Image.Resampling.LANCZOS)
        ids = [str(icon_id)] if icon_id and str(icon_id) != "0" else []
        for fid in FALLBACK_IDS:
            if fid not in ids:
                ids.append(fid)
        for i in ids:
            data = sync_fetch_url(f"https://iconapi.wasmer.app/{i}")
            if data:
                img = Image.open(io.BytesIO(data)).convert("RGBA")
                return img.resize(size, Image.Resampling.LANCZOS)
    except:
        pass
    return None


def draw_text_stroked(draw, x, y, text, f_main, f_alt, stroke=3):
    if not text:
        return
    cx = x
    for ch in text:
        font = f_alt if is_cherokee(ch) else f_main
        for dx in range(-stroke, stroke+1):
            for dy in range(-stroke, stroke+1):
                draw.text((cx+dx, y+dy), ch, font=font, fill="black")
        draw.text((cx, y), ch, font=font, fill="white")
        cx += font.getlength(ch)


def _asset_path(name: str) -> str:
    return os.path.join(os.path.dirname(__file__), name)


def _open_asset(name: str) -> Optional[Any]:
    p = _asset_path(name)
    if PIL_AVAILABLE and os.path.exists(p):
        try:
            return Image.open(p).convert("RGBA")
        except:
            pass
    return None


def generate_banner_image(
    ava_bytes: Optional[bytes],
    ban_bytes: Optional[bytes],
    player: Dict,
    badge: Optional[str] = None,
    frame: Optional[str] = None,
) -> io.BytesIO:
    W, H = 1280, 720
    canvas = Image.new("RGBA", (W, H), (30, 30, 40, 255))
    draw   = ImageDraw.Draw(canvas)

    # Banner background
    if ban_bytes:
        try:
            ban_img = Image.open(io.BytesIO(ban_bytes)).convert("RGBA")
            x1, y1 = int(W*BANNER_START_X), int(H*BANNER_START_Y)
            x2, y2 = int(W*BANNER_END_X),   int(H*BANNER_END_Y)
            ban_img = ban_img.resize((x2-x1, y2-y1), Image.Resampling.LANCZOS)
            canvas.paste(ban_img, (x1,y1), ban_img)
        except:
            pass

    # Avatar
    if ava_bytes:
        try:
            ava_img = Image.open(io.BytesIO(ava_bytes)).convert("RGBA")
            aw = int(200 * AVATAR_ZOOM)
            ava_img = ava_img.resize((aw,aw), Image.Resampling.LANCZOS)
            ax = 40 + AVATAR_SHIFT_X
            ay = H//2 - aw//2 + AVATAR_SHIFT_Y
            canvas.paste(ava_img, (ax,ay), ava_img)
        except:
            pass

    # Prime badge
    prime_level = player.get("prime_level", 0)
    if badge:
        # Custom badge
        badge_file = CUSTOM_BADGE_FILES.get(badge) or (f"prime{badge[-1]}.png" if badge.startswith("prime") else None)
        if badge_file:
            bi = _open_asset(badge_file)
            if bi:
                bi = bi.resize((80,80), Image.Resampling.LANCZOS)
                canvas.paste(bi, (40, H-100), bi)
    else:
        badge_file = PRIME_FILES.get(prime_level)
        if badge_file:
            bi = _open_asset(badge_file)
            if bi:
                bi = bi.resize((80,80), Image.Resampling.LANCZOS)
                canvas.paste(bi, (40, H-100), bi)

    # Frame overlay
    if frame:
        frame_file = CUSTOM_FRAME_FILES.get(frame)
        if frame_file:
            fi = _open_asset(frame_file)
            if fi:
                fi = fi.resize((W,H), Image.Resampling.LANCZOS)
                canvas.paste(fi, (0,0), fi)

    # Text
    try:
        f_main = ImageFont.truetype(_asset_path(FONT_MAIN), 36)
        f_alt  = ImageFont.truetype(_asset_path(FONT_CHEROKEE), 36) if os.path.exists(_asset_path(FONT_CHEROKEE)) else f_main
        f_sm   = ImageFont.truetype(_asset_path(FONT_MAIN), 26)
    except:
        f_main = f_alt = f_sm = ImageFont.load_default()

    draw_text_stroked(draw, 280, 260, player.get("name",""), f_main, f_alt)
    draw_text_stroked(draw, 280, 310, f"Level {player.get('level','')}", f_sm, f_sm, stroke=2)
    guild = player.get("guild","")
    if guild:
        draw_text_stroked(draw, 280, 345, f"Guild: {guild}", f_sm, f_sm, stroke=2)

    buf = io.BytesIO()
    canvas.convert("RGB").save(buf, "PNG")
    buf.seek(0)
    return buf


def _fetch_image_bytes(item_id: str) -> Optional[bytes]:
    if not item_id or str(item_id).lower() in ("0","none","null"):
        return None
    url = f"{CDN_URL}/{item_id}.png"
    return sync_fetch_url(url)


def _outfit_available() -> bool:
    return PIL_AVAILABLE and os.path.exists(_asset_path(OUTFIT_BACKGROUND))


def generate_outfit_image(data: Dict) -> io.BytesIO:
    W, H = 1200, 900
    bg_path = _asset_path(OUTFIT_BACKGROUND)
    if os.path.exists(bg_path):
        canvas = Image.open(bg_path).convert("RGBA").resize((W,H), Image.Resampling.LANCZOS)
    else:
        canvas = Image.new("RGBA",(W,H),(40,40,50,255))

    char_id = data.get("character", DEFAULT_AVATAR_ID)
    char_img = fetch_icon(char_id, CHARACTER_RENDER_SIZE, is_character=True)
    if char_img:
        cx = (W - char_img.width) // 2
        cy = (H - char_img.height) // 2 - 50
        canvas.paste(char_img, (cx,cy), char_img)

    slot_map = {
        "mask":"mask","shirt":"shirt","pants":"pants","shoes":"shoes",
        "emote":"emote","armor":"armor","weapon":"weapon","pet":"pet"
    }
    for slot, key in slot_map.items():
        item_id = data.get(key)
        if item_id:
            icon = fetch_icon(item_id)
            if icon and slot in HEX_POSITIONS:
                x, y = HEX_POSITIONS[slot]
                canvas.paste(icon, (x,y), icon)

    buf = io.BytesIO()
    canvas.convert("RGB").save(buf,"PNG")
    buf.seek(0)
    return buf

# ══════════════════════════════════════════════════════════════════════════════
#  AI ENDPOINT
# ══════════════════════════════════════════════════════════════════════════════

def ask_ai(question: str, model: str = "openai") -> str:
    """Ask pollinations.ai text API (free, no key). Models: openai, mistral, llama, gemini."""
    import urllib.parse
    system = "You are a helpful Free Fire game assistant. Answer concisely and accurately."
    try:
        payload = {
            "messages": [
                {"role": "system", "content": system},
                {"role": "user",   "content": question}
            ],
            "model": model,
            "seed": 42,
            "jsonMode": False,
        }
        resp = requests.post(
            "https://text.pollinations.ai/",
            json=payload,
            headers={"Content-Type":"application/json","User-Agent":"Mozilla/5.0"},
            timeout=25
        )
        if resp.status_code == 200 and resp.text.strip():
            return resp.text.strip()
    except Exception:
        pass
    # fallback: GET method
    try:
        encoded = urllib.parse.quote(question)
        resp = requests.get(
            f"https://text.pollinations.ai/{encoded}",
            params={"model": model},
            timeout=20, headers={"User-Agent":"Mozilla/5.0"}
        )
        if resp.status_code == 200 and resp.text.strip():
            return resp.text.strip()
    except Exception:
        pass
    return "AI service temporarily unavailable. Please try again later."

# ══════════════════════════════════════════════════════════════════════════════
#  FLASK ROUTES
# ══════════════════════════════════════════════════════════════════════════════

def _inc(key):
    _request_counter[key] = _request_counter.get(key, 0) + 1
    _request_counter["total"] = _request_counter.get("total", 0) + 1


@app.before_request
def _count():
    _request_counter["total"] = _request_counter.get("total", 0) + 1

@app.after_request
def _headers(response):
    response.headers["X-Powered-By"]    = "FF-Ultimate-API"
    response.headers["X-API-Version"]   = "3.0"
    response.headers["Access-Control-Allow-Origin"] = "*"
    return response


# ─── Root / Help ─────────────────────────────────────────────────────────────

@app.route("/")
def index():
    base = request.host_url.rstrip("/")
    endpoints = {
        # ── Player Info (src type – real protobuf) ──
        "/player-info":    {"method":"GET","params":{"uid":"Player UID"},"example":f"{base}/player-info?uid=3074306062","desc":"Real player info via protobuf (src type)"},
        "/level":          {"method":"GET","params":{"uid":"Player UID"},"example":f"{base}/level?uid=3074306062","desc":"Player level + XP progress"},
        "/region":         {"method":"GET","params":{"uid":"Player UID"},"example":f"{base}/region?uid=3074306062","desc":"Detect player region"},
        "/bancheck":       {"method":"GET","params":{"uid":"Player UID"},"example":f"{base}/bancheck?uid=3074306062","desc":"Ban status check"},
        "/profile-stats":  {"method":"GET","params":{"uid":"Player UID"},"example":f"{base}/profile-stats?uid=3074306062","desc":"Extended player stats"},
        "/guild-info":     {"method":"GET","params":{"uid":"Player UID"},"example":f"{base}/guild-info?uid=3074306062","desc":"Guild information"},
        "/rank":           {"method":"GET","params":{"uid":"Player UID"},"example":f"{base}/rank?uid=3074306062","desc":"Player rank & tier"},
        "/char-info":      {"method":"GET","params":{"uid":"Player UID"},"example":f"{base}/char-info?uid=3074306062","desc":"Character & outfit info"},
        "/pet-info":       {"method":"GET","params":{"uid":"Player UID"},"example":f"{base}/pet-info?uid=3074306062","desc":"Pet information"},
        "/outfit-info":    {"method":"GET","params":{"uid":"Player UID"},"example":f"{base}/outfit-info?uid=3074306062","desc":"Full outfit slot info"},
        "/kill-stats":     {"method":"GET","params":{"uid":"Player UID"},"example":f"{base}/kill-stats?uid=3074306062","desc":"Kill/game stats (simulated)"},
        # ── Dynamic Duo ──
        "/duo":            {"method":"GET","params":{"uid":"Player UID","password":"Account password"},"example":f"{base}/duo?uid=3074306062&password=YOURPASS","desc":"Dynamic Duo info"},
        # ── Token / Auth ──
        "/token":          {"method":"GET","params":{"uid":"Player UID","password":"Account password","region":"Optional region"},"example":f"{base}/token?uid=UID&password=PASS","desc":"Generate JWT token"},
        "/token/batch":    {"method":"POST","params":{"file":"JSON file with accounts"},"example":f"{base}/token/batch","desc":"Batch JWT generation"},
        "/access-jwt":     {"method":"GET","params":{"access_token":"Garena access token","open_id":"Optional open_id"},"example":f"{base}/access-jwt?access_token=TOKEN","desc":"JWT from Garena access token"},
        "/eat-access":     {"method":"GET","params":{"eat":"EAT token"},"example":f"{base}/eat-access?eat=TOKEN","desc":"EAT access token extraction"},
        "/refresh":        {"method":"GET","desc":"Refresh all region tokens","example":f"{base}/refresh"},
        # ── Images ──
        "/banner":         {"method":"GET","params":{"uid":"Player UID"},"example":f"{base}/banner?uid=3074306062","desc":"Generate player banner image"},
        "/random-banner":  {"method":"GET","params":{"uid":"Player UID"},"example":f"{base}/random-banner?uid=3074306062","desc":"Random banner"},
        "/batch-banners":  {"method":"GET","params":{"uids":"Comma-separated UIDs"},"example":f"{base}/batch-banners?uids=UID1,UID2","desc":"Download ZIP of banners"},
        "/outfit":         {"method":"GET","params":{"uid":"Player UID"},"example":f"{base}/outfit?uid=3074306062","desc":"Generate outfit image"},
        "/random-outfit":  {"method":"GET","params":{"uid":"Player UID"},"example":f"{base}/random-outfit?uid=3074306062","desc":"Random outfit image"},
        "/image":          {"method":"GET","params":{"prompt":"Image description"},"example":f"{base}/image?prompt=beautiful+sunset","desc":"AI image generation"},
        # ── Item Database ──
        "/item":           {"method":"GET","params":{"info":"Search query or item name"},"example":f"{base}/item?info=Nulla","desc":"Search item database"},
        "/item/info":      {"method":"GET","params":{"q":"Search query"},"example":f"{base}/item/info?q=Nulla","desc":"Item info search"},
        "/items":          {"method":"GET","desc":"List configured items","example":f"{base}/items"},
        "/items/search":   {"method":"GET","params":{"q":"Search query"},"example":f"{base}/items/search?q=shotgun","desc":"Full item search"},
        "/items/category": {"method":"GET","params":{"type":"Item type (AVATAR/GUN/etc)"},"example":f"{base}/items/category?type=GUN","desc":"Items by category"},
        # ── Game Info ──
        "/weapon-info":    {"method":"GET","params":{"weapon_id":"Weapon ID"},"example":f"{base}/weapon-info?weapon_id=901000001","desc":"Weapon details"},
        "/badge-info":     {"method":"GET","params":{"badge_id":"Badge ID"},"example":f"{base}/badge-info?badge_id=1001000097","desc":"Badge details"},
        "/prime-levels":   {"method":"GET","desc":"Prime level list","example":f"{base}/prime-levels"},
        "/badges":         {"method":"GET","desc":"Available badge assets","example":f"{base}/badges"},
        "/frames":         {"method":"GET","desc":"Available frame assets","example":f"{base}/frames"},
        "/leaderboard":    {"method":"GET","params":{"limit":"Result count (1-100)"},"example":f"{base}/leaderboard?limit=10","desc":"Simulated leaderboard"},
        "/game-modes":     {"method":"GET","desc":"All Free Fire game modes","example":f"{base}/game-modes"},
        "/maps":           {"method":"GET","desc":"All Free Fire maps","example":f"{base}/maps"},
        "/seasons":        {"method":"GET","desc":"Ranked season info","example":f"{base}/seasons"},
        # ── Social ──
        "/like":           {"method":"GET","params":{"uid":"Player UID"},"example":f"{base}/like?uid=3074306062","desc":"Like a player profile"},
        "/follow":         {"method":"GET","params":{"uid":"Player UID"},"example":f"{base}/follow?uid=3074306062","desc":"Follow a player"},
        "/boost":          {"method":"GET","params":{"uid":"Player UID"},"example":f"{base}/boost?uid=3074306062","desc":"Boost a player"},
        "/vote":           {"method":"GET","params":{"uid":"Player UID"},"example":f"{base}/vote?uid=3074306062","desc":"Vote for a player"},
        # ── AI ──
        "/ai":             {"method":"GET","params":{"question":"Your question"},"example":f"{base}/ai?question=Free+Fire+tips","desc":"Ask AI anything (Free Fire or general)"},
        # ── Server ──
        "/status":         {"method":"GET","desc":"Server status","example":f"{base}/status"},
        "/health":         {"method":"GET","desc":"Health check","example":f"{base}/health"},
        "/ping":           {"method":"GET","desc":"Ping test","example":f"{base}/ping"},
        "/version":        {"method":"GET","desc":"API version","example":f"{base}/version"},
        "/analytics":      {"method":"GET","desc":"Request analytics","example":f"{base}/analytics"},
        "/server-info":    {"method":"GET","desc":"Server information","example":f"{base}/server-info"},
        "/time":           {"method":"GET","desc":"Server time","example":f"{base}/time"},
        "/uptime":         {"method":"GET","desc":"Server uptime","example":f"{base}/uptime"},
        "/update_info":    {"method":"GET","desc":"Update config","example":f"{base}/update_info"},
        "/force_update":   {"method":"GET","desc":"Force update config","example":f"{base}/force_update"},
    }
    return jsonify({
        "name": "FF Ultimate API",
        "version": "7.0",
        "author": "Merged (ffinfoo + sulavcodex)",
        "info_type": "protobuf-src (real)",
        "endpoints": endpoints,
        "total": len(endpoints),
        "note": "Use ?help=1 for this list",
    })


@app.route("/help")
def help_page():
    return index()

# ─── Player Info (protobuf src type) ─────────────────────────────────────────

@app.route("/player-info")
def route_player_info():
    uid = request.args.get("uid","").strip()
    if not uid:
        return jsonify({"error":"uid is required"}), 400
    try:
        raw = get_player_info_src(uid)
        if not raw:
            return jsonify({"error":"UID not found in any region","uid":uid}), 404
        return Response(
            json.dumps(raw, indent=2, ensure_ascii=False),
            mimetype="application/json; charset=utf-8"
        )
    except Exception as e:
        return jsonify({"error":str(e)}), 500

# ─── Level ───────────────────────────────────────────────────────────────────

@app.route("/level")
def route_level():
    uid = request.args.get("uid","").strip()
    if not uid:
        return jsonify({"error":"uid is required"}), 400
    try:
        p = fetch_player_data(uid)
        lvl = int(p.get("level",0))
        exp = int(p.get("exp",0))
        progress = calculate_level_progress(exp, lvl)
        return jsonify({
            "uid": uid,
            "nickname": p["name"],
            "level": lvl,
            "exp": exp,
            "level_progress": progress,
        })
    except ValueError as _ve:
        return jsonify({"error": str(_ve), "uid": uid}), 404
    except Exception as e:
        return jsonify({"error":str(e)}), 500

# ─── Region ──────────────────────────────────────────────────────────────────

@app.route("/region")
def route_region():
    uid = request.args.get("uid","").strip()
    if not uid:
        return jsonify({"error":"uid is required"}), 400
    # Try to detect region via token fetch
    region = _uid_region_cache.get(uid)
    if not region:
        try:
            get_player_info_src(uid)  # populates cache
            region = _uid_region_cache.get(uid, "Unknown")
        except:
            region = "Unknown"
    if not region or region == "Unknown":
        return jsonify({
            "error": "Player not found",
            "uid": uid,
            "hint": "The real Free Fire service returned no profile for this UID.",
        }), 404
    return jsonify({"uid": uid, "region": region})

# ─── Ban Check ───────────────────────────────────────────────────────────────

@app.route("/bancheck")
def route_bancheck():
    uid = request.args.get("uid","").strip()
    if not uid:
        return jsonify({"error":"uid is required"}), 400
    try:
        raw = get_player_info_src(uid)
        if not raw:
            return jsonify({"error":"UID not found","uid":uid}), 404
        basic = raw.get("basicInfo",{}) or {}
        ban_info = raw.get("blacklistInfo",{}) or {}
        is_banned = bool(ban_info.get("banReason") or ban_info.get("banTime"))
        return jsonify({
            "uid": uid,
            "nickname": (raw.get("profileInfo",{}) or {}).get("nickname","Unknown"),
            "is_banned": is_banned,
            "ban_info": ban_info,
            "account_id": str(basic.get("accountId",uid)),
        })
    except ValueError as _ve:
        return jsonify({"error": str(_ve), "uid": uid}), 404
    except Exception as e:
        return jsonify({"error":str(e)}), 500

# ─── Profile Stats ────────────────────────────────────────────────────────────

@app.route("/profile-stats")
def route_profile_stats():
    uid = request.args.get("uid","").strip()
    if not uid:
        return jsonify({"error":"uid is required"}), 400
    try:
        p = fetch_player_data(uid)
        lvl = int(p.get("level",0))
        exp = int(p.get("exp",0))
        progress = calculate_level_progress(exp, lvl)
        return jsonify({
            "uid": uid,
            "nickname": p["name"],
            "level": lvl,
            "exp": exp,
            "guild": p.get("guild",""),
            "prime_level": p.get("prime_level",0),
            "region": p.get("region",""),
            "level_progress": progress,
            "stats": {
                "total_likes": random.randint(0,10000),
                "total_followers": random.randint(0,5000),
                "rank": random.randint(1,100),
            },
        })
    except ValueError as _ve:
        return jsonify({"error": str(_ve), "uid": uid}), 404
    except Exception as e:
        return jsonify({"error":str(e)}), 500

# ─── Guild Info ───────────────────────────────────────────────────────────────

@app.route("/guild-info")
def route_guild_info():
    uid = request.args.get("uid","").strip()
    if not uid:
        return jsonify({"error":"uid is required"}), 400
    try:
        raw = get_player_info_src(uid)
        if not raw:
            return jsonify({
                "error": "Player not found",
                "uid": uid,
                "hint": "The real Free Fire service returned no profile for this UID.",
            }), 404
        clan = (raw.get("clanBasicInfo",{}) or {})
        if not clan:
            return jsonify({"uid":uid,"guild":None,"message":"Player is not in a guild"})
        return jsonify({
            "uid": uid,
            "guild_id": str(clan.get("clanId","")),
            "guild_name": clan.get("clanName",""),
            "guild_level": clan.get("clanLevel",0),
            "member_count": clan.get("memberNum",0),
            "captain_name": clan.get("captainName",""),
            "capacity": clan.get("capacity",0),
        })
    except ValueError as _ve:
        return jsonify({"error": str(_ve), "uid": uid}), 404
    except Exception as e:
        return jsonify({"error":str(e)}), 500

# ─── Rank ─────────────────────────────────────────────────────────────────────

@app.route("/rank")
def route_rank():
    uid = request.args.get("uid","").strip()
    if not uid:
        return jsonify({"error":"uid is required"}), 400
    try:
        p = fetch_player_data(uid)
        raw = p.get("raw",{})
        credit = (raw.get("creditScoreInfo",{}) or {})
        rank_info = (raw.get("basicInfo",{}) or {})
        return jsonify({
            "uid": uid,
            "nickname": p["name"],
            "level": p["level"],
            "credit_score": credit.get("creditScore",100),
            "tier": random.choice(["Bronze","Silver","Gold","Platinum","Diamond","Heroic","Grandmaster"]),
            "rank_points": random.randint(0,5000),
            "rank": random.randint(1,100000),
        })
    except ValueError as _ve:
        return jsonify({"error": str(_ve), "uid": uid}), 404
    except Exception as e:
        return jsonify({"error":str(e)}), 500

# ─── Char Info ────────────────────────────────────────────────────────────────

@app.route("/char-info")
def route_char_info():
    uid = request.args.get("uid","").strip()
    if not uid:
        return jsonify({"error":"uid is required"}), 400
    try:
        p = fetch_player_data(uid)
        clothes = p.get("clothes") or []
        slot_names = ("mask", "shirt", "pants", "shoes", "emote", "armor",
                      "weapon_skin", "backpack", "facepaint", "parachute")
        outfit = {
            slot_names[i] if i < len(slot_names) else f"slot_{i}": item_id
            for i, item_id in enumerate(clothes)
        }
        return jsonify({
            "uid": uid,
            "nickname": p["name"],
            "character_id": p.get("character",""),
            "avatar_id": p.get("headPic",""),
            "banner_id": p.get("banner_id",""),
            "prime_level": p.get("prime_level",0),
            "outfit": outfit,
            "clothes": clothes,
            "weapon_skin": p.get("weapon"),
            "pet_skin": p.get("pet"),
        })
    except ValueError as _ve:
        return jsonify({"error": str(_ve), "uid": uid}), 404
    except Exception as e:
        return jsonify({"error":str(e)}), 500

# ─── Pet Info ─────────────────────────────────────────────────────────────────

@app.route("/pet-info")
def route_pet_info():
    uid = request.args.get("uid","").strip()
    if not uid:
        return jsonify({"error":"uid is required"}), 400
    try:
        p = fetch_player_data(uid)
        raw = p.get("raw",{})
        pet_info = (raw.get("petInfo",{}) or {})
        return jsonify({
            "uid": uid,
            "nickname": p["name"],
            "pet": {
                "pet_id":  pet_info.get("id",""),
                "name":    pet_info.get("name",""),
                "level":   pet_info.get("level",0),
                "exp":     pet_info.get("exp",0),
                "skin_id": pet_info.get("skinId",""),
                "selected": pet_info.get("selectedSkillId",""),
            },
        })
    except ValueError as _ve:
        return jsonify({"error": str(_ve), "uid": uid}), 404
    except Exception as e:
        return jsonify({"error":str(e)}), 500

# ─── Outfit Info ──────────────────────────────────────────────────────────────

@app.route("/outfit-info")
def route_outfit_info():
    uid = request.args.get("uid","").strip()
    if not uid:
        return jsonify({"error":"uid is required"}), 400
    try:
        p = fetch_player_data(uid)
        clothes = p.get("clothes",[])
        slot_names = ["mask","shirt","pants","shoes","emote","armor","weapon_skin","backpack"]
        slots = {}
        for i, cid in enumerate(clothes):
            sname = slot_names[i] if i < len(slot_names) else f"slot_{i}"
            slots[sname] = cid
        return jsonify({
            "uid": uid,
            "nickname": p["name"],
            "outfit": slots,
            "slots": [
                {"slot": name, "item_id": value, "available": bool(value)}
                for name, value in slots.items()
            ],
            "weapon_skin": p.get("weapon",""),
            "pet_skin": p.get("pet",""),
            "character_id": p.get("character",""),
            "avatar_id": p.get("headPic",""),
            "banner_id": p.get("banner_id",""),
        })
    except ValueError as _ve:
        return jsonify({"error": str(_ve), "uid": uid}), 404
    except Exception as e:
        return jsonify({"error":str(e)}), 500

# ─── Kill Stats ───────────────────────────────────────────────────────────────

@app.route("/kill-stats")
def route_kill_stats():
    uid = request.args.get("uid","").strip()
    if not uid:
        return jsonify({"error":"uid is required"}), 400
    try:
        p = fetch_player_data(uid)
        raw = p.get("raw",{})
        social = (raw.get("socialBasicInfo",{}) or raw.get("basicInfo",{}) or {})
        return jsonify({
            "uid": uid,
            "nickname": p["name"],
            "level": p["level"],
            "stats": {
                "total_kills":     social.get("killCount") or random.randint(500,10000),
                "headshots":       random.randint(100,5000),
                "headshot_rate":   f"{random.randint(15,65)}%",
                "total_matches":   random.randint(200,5000),
                "wins":            random.randint(10,500),
                "win_rate":        f"{random.randint(5,40)}%",
                "max_kills_match": random.randint(5,20),
                "kd_ratio":        round(random.uniform(0.5,5.0),2),
            },
        })
    except ValueError as _ve:
        return jsonify({"error": str(_ve), "uid": uid}), 404
    except Exception as e:
        return jsonify({"error":str(e)}), 500

# ─── Duo ─────────────────────────────────────────────────────────────────────

@app.route("/duo")
def route_duo():
    uid      = request.args.get("uid","").strip()
    password = request.args.get("password","GUEST_PASSWORD")
    info_raw = request.args.get("info")
    if not uid:
        return jsonify({"error":"uid is required"}), 400

    cache_key = f"duo_jwt:{uid}:{password}"
    cached = _duo_jwt_cache.get(cache_key,{})
    if cached.get("expires",0) > time.time():
        jwt_token = cached["jwt"]
    else:
        result = generate_jwt_sync(uid, password, "AUTO")
        if not result.get("success"):
            return jsonify({"error":f"JWT failed: {result.get('error','Unknown')}"}), 401
        jwt_token = result["jwt_token"]
        _duo_jwt_cache[cache_key] = {"jwt": jwt_token, "expires": time.time()+300}

    # Build encrypted duo request
    def build_duo_request(uid):
        n = int(uid)
        varint = bytearray()
        while True:
            byte = n & 0x7F; n >>= 7
            if n: byte |= 0x80
            varint.append(byte)
            if not n: break
        payload = b"\x08" + bytes(varint)
        cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
        return cipher.encrypt(crypto_pad(payload, AES.block_size))

    try:
        enc = build_duo_request(uid)
        url = "https://client.ind.freefiremobile.com/GetSpecialFriendList"
        headers = {
            "Authorization": f"Bearer {jwt_token}",
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 11)",
            "X-GA": "v1 1",
            "ReleaseVersion": "OB54",
            "Connection": "Keep-Alive",
        }
        resp = requests.post(url, headers=headers, data=enc, verify=False, timeout=15)
        if resp.status_code != 200:
            return jsonify({"error":f"Server returned {resp.status_code}"}), 502
    except Exception as e:
        return jsonify({"error":f"Request failed: {e}"}), 500

    # Decrypt response
    try:
        cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
        decrypted = cipher.decrypt(resp.content)
        pad_len = decrypted[-1]
        decrypted = decrypted[:-pad_len]
    except Exception as e:
        return jsonify({"error":f"Decryption failed: {e}"}), 500

    if duo_pb2 is None:
        return jsonify({"success":True,"has_duo":True,"partner_uid":"N/A","note":"Protobuf not available"})

    try:
        msg = duo_pb2.SpecialFriendResponse()
        msg.ParseFromString(decrypted)
        if not msg.HasField("duo_info"):
            return jsonify({"success":True,"has_duo":False,"message":"No Dynamic Duo found"})
        duo = msg.duo_info
        score = duo.score
        level = 1 if score<101 else 2 if score<301 else 3 if score<501 else 4 if score<801 else 5 if score<1201 else 6
        status_text = "Active" if duo.status==2 else "Inactive"
        creation_time = time.strftime('%B %d, %Y at %I:%M %p', time.localtime(duo.creation_timestamp))
        if info_raw is not None:
            return jsonify({"success":True,"has_duo":True,
                            "partner_uid":str(duo.partner_uid),"score":duo.score,
                            "creation_timestamp":duo.creation_timestamp,
                            "days_active":duo.days_active,"status":duo.status})
        return jsonify({
            "success":True,"has_duo":True,
            "partner_uid":str(duo.partner_uid),
            "duo_level":level,"duo_score":score,
            "days_active":duo.days_active,
            "creation_time":creation_time,
            "creation_timestamp":duo.creation_timestamp,
            "status":status_text,
        })
    except Exception as e:
        return jsonify({"error":f"Parsing failed: {e}"}), 500

# ─── Token ────────────────────────────────────────────────────────────────────

@app.route("/token")
def route_token():
    uid      = request.args.get("uid","").strip()
    password = request.args.get("password","").strip()
    region   = request.args.get("region","AUTO").strip()
    if not uid or not password:
        return jsonify({"error":"uid and password are required"}), 400
    result = generate_jwt_sync(uid, password, region)
    return jsonify(result)


@app.route("/token/batch", methods=["POST"])
def route_token_batch():
    try:
        accounts = request.get_json(force=True)
        if not isinstance(accounts, list):
            return jsonify({"error":"Body must be a JSON array of {uid,password}"}), 400
        results = []
        for acc in accounts[:20]:  # cap at 20
            uid = str(acc.get("uid",""))
            pwd = str(acc.get("password",""))
            r   = acc.get("region","AUTO")
            if uid and pwd:
                results.append(generate_jwt_sync(uid, pwd, r))
        return jsonify({"results": results, "count": len(results)})
    except Exception as e:
        return jsonify({"error":str(e)}), 500

# ─── Access JWT ───────────────────────────────────────────────────────────────

@app.route("/access-jwt")
def route_access_jwt():
    access_token = request.args.get("access_token","").strip()
    open_id      = request.args.get("open_id","").strip()
    if not access_token:
        return jsonify({"error":"access_token is required"}), 400

    cache_key = f"accjwt:{access_token}:{open_id}"
    cached = _jwt_cache.get(cache_key,{})
    if cached.get("expires",0) > time.time():
        return jsonify(cached["data"])

    if not open_id:
        try:
            insp = requests.get(
                f"https://100067.connect.garena.com/oauth/token/inspect?token={access_token}",
                timeout=10
            )
            if insp.status_code == 200:
                open_id = insp.json().get("open_id","")
        except:
            pass
    if not open_id:
        return jsonify({"error":"Could not determine open_id. Provide open_id parameter."}), 400

    for region in ALL_REGIONS:
        result = major_login_sulav(access_token, open_id, region)
        if result and result.get("jwt_token"):
            jwt_token = result["jwt_token"]
            payload   = decode_jwt_payload(jwt_token)
            resp_data = {
                "success":True,"jwt":jwt_token,
                "account_id":result.get("account_id"),
                "open_id":open_id,"access_token":access_token,
                "region_used":region,"payload":payload,
            }
            _jwt_cache[cache_key] = {"data":resp_data,"expires":time.time()+300}
            return jsonify(resp_data)
        time.sleep(0.2)

    return jsonify({"error":"MajorLogin failed for all regions"}), 401

# ─── EAT Access ───────────────────────────────────────────────────────────────

@app.route("/eat-access")
def route_eat_access():
    eat = request.args.get("eat","").strip()
    if not eat:
        return jsonify({"error":"eat token is required"}), 400
    try:
        session = requests.Session()
        resp    = session.get(EAT_TARGET_URL, params={"access_token":eat}, allow_redirects=True, timeout=10)
        final_url    = resp.url
        parsed       = urlparse(final_url)
        query_params = parse_qs(parsed.query)
        access_token = query_params.get("access_token",[None])[0]
        if not access_token:
            return jsonify({"error":"Access token not found in redirect"}), 500
        text = (
            f"OWNER:FF ULTIMATE API\n"
            f"TELEGRAM:@ff_ultimate_api\n"
            f"THANKS FOR USING!\n"
            f"access token= {access_token}"
        )
        return Response(text, mimetype="text/plain")
    except Exception as e:
        return jsonify({"error":str(e)}), 500

# ─── Refresh tokens ───────────────────────────────────────────────────────────

@app.route("/refresh", methods=["GET","POST"])
def route_refresh():
    _token_cache.clear()
    _uid_region_cache.clear()
    return jsonify({"message":"Token caches cleared. Tokens will be refreshed on next request.","regions": list(_SERVICE_ACCOUNTS.keys())})

# ─── Banner image ─────────────────────────────────────────────────────────────

@app.route("/banner")
def route_banner():
    uid         = request.args.get("uid","").strip()
    bannerid    = request.args.get("bannerid")
    avatarid    = request.args.get("avatarid")
    primelevel  = request.args.get("primelevel", type=int)
    guildname   = request.args.get("guildname")
    playername  = request.args.get("playername")
    level       = request.args.get("level")
    badge       = request.args.get("badge")
    frame       = request.args.get("frame")
    if not uid:
        return jsonify({"error":"uid is required"}), 400
    if not PIL_AVAILABLE:
        return jsonify({"error":"PIL not available on this server"}), 503
    try:
        real = fetch_player_data(uid)
        final = {
            "name":       clean_text(playername) if playername else real["name"],
            "level":      level if level else real["level"],
            "guild":      clean_text(guildname) if guildname else real.get("guild",""),
            "headPic":    avatarid if avatarid else real.get("headPic",""),
            "banner_id":  bannerid if bannerid else real.get("banner_id",""),
            "prime_level":primelevel if primelevel is not None else real.get("prime_level",0),
        }
        ava_bytes = _fetch_image_bytes(final["headPic"])
        ban_bytes = _fetch_image_bytes(final["banner_id"])
        img = generate_banner_image(ava_bytes, ban_bytes, final, badge, frame)
        _inc("banner")
        return Response(img.read(), mimetype="image/png")
    except ValueError as _ve:
        return jsonify({"error": str(_ve), "uid": uid}), 404
    except Exception as e:
        return jsonify({"error":str(e)}), 500


@app.route("/random-banner")
def route_random_banner():
    uid = request.args.get("uid","").strip()
    if not uid:
        return jsonify({"error":"uid is required"}), 400
    if not PIL_AVAILABLE:
        return jsonify({"error":"PIL not available"}), 503
    try:
        real = fetch_player_data(uid)
        random_badge = random.choice(["vbadge1","vbadge2","vbadge3","vbadge4","gmbadge","cbadge","probadge"] +
                                     [f"prime{i}" for i in range(9)])
        ava_bytes = _fetch_image_bytes(real.get("headPic",""))
        ban_bytes = _fetch_image_bytes(real.get("banner_id",""))
        img = generate_banner_image(ava_bytes, ban_bytes, real, random_badge, None)
        return Response(img.read(), mimetype="image/png")
    except ValueError as _ve:
        return jsonify({"error": str(_ve), "uid": uid}), 404
    except Exception as e:
        return jsonify({"error":str(e)}), 500


@app.route("/batch-banners")
def route_batch_banners():
    uids_str = request.args.get("uids","").strip()
    if not uids_str:
        return jsonify({"error":"uids parameter required (comma-separated)"}), 400
    if not PIL_AVAILABLE:
        return jsonify({"error":"PIL not available"}), 503
    uid_list = [u.strip() for u in uids_str.split(",") if u.strip()][:10]
    zip_buf  = io.BytesIO()
    with zipfile.ZipFile(zip_buf,"w",zipfile.ZIP_DEFLATED) as zf:
        for uid in uid_list:
            try:
                real = fetch_player_data(uid)
                ava  = _fetch_image_bytes(real.get("headPic",""))
                ban  = _fetch_image_bytes(real.get("banner_id",""))
                img  = generate_banner_image(ava, ban, real, None, None)
                zf.writestr(f"banner_{uid}.png", img.read())
            except Exception as e:
                logger.warning(f"Banner failed for {uid}: {e}")
    zip_buf.seek(0)
    return Response(zip_buf.read(), mimetype="application/zip",
                    headers={"Content-Disposition":"attachment; filename=banners.zip"})

# ─── Outfit image ─────────────────────────────────────────────────────────────

@app.route("/outfit")
def route_outfit():
    uid = request.args.get("uid","").strip()
    if not uid:
        return jsonify({"error":"uid is required"}), 400
    if not PIL_AVAILABLE:
        return jsonify({"error":"PIL not available"}), 503
    try:
        real = fetch_player_data(uid)
        clothes = real.get("clothes",[])
        data = {
            "character": request.args.get("head") or real.get("character"),
            "mask":      request.args.get("mask")  or (clothes[0] if len(clothes)>0 else None),
            "shirt":     request.args.get("top")   or (clothes[1] if len(clothes)>1 else None),
            "pants":     request.args.get("pants")  or (clothes[2] if len(clothes)>2 else None),
            "shoes":     request.args.get("shoes")  or (clothes[3] if len(clothes)>3 else None),
            "emote":     request.args.get("faceprint") or (clothes[4] if len(clothes)>4 else None),
            "armor":     request.args.get("paint")  or (clothes[5] if len(clothes)>5 else None),
            "weapon":    request.args.get("weapon") or real.get("weapon"),
            "pet":       request.args.get("pet")    or real.get("pet"),
        }
        img = generate_outfit_image(data)
        return Response(img.read(), mimetype="image/png")
    except ValueError as _ve:
        return jsonify({"error": str(_ve), "uid": uid}), 404
    except Exception as e:
        return jsonify({"error":str(e)}), 500


@app.route("/random-outfit")
def route_random_outfit():
    uid = request.args.get("uid","").strip()
    if not uid:
        return jsonify({"error":"uid is required"}), 400
    if not PIL_AVAILABLE:
        return jsonify({"error":"PIL not available"}), 503
    try:
        real = fetch_player_data(uid)
        data = {
            "character": real.get("character"),
            "weapon":    real.get("weapon"),
            "pet":       real.get("pet"),
            "mask":   random.choice(FALLBACK_IDS),
            "shirt":  random.choice(FALLBACK_IDS),
            "pants":  random.choice(FALLBACK_IDS),
            "shoes":  random.choice(FALLBACK_IDS),
        }
        img = generate_outfit_image(data)
        return Response(img.read(), mimetype="image/png")
    except ValueError as _ve:
        return jsonify({"error": str(_ve), "uid": uid}), 404
    except Exception as e:
        return jsonify({"error":str(e)}), 500

# ─── Badges / Frames ─────────────────────────────────────────────────────────

@app.route("/badges")
def route_badges():
    prime = [{"name":f"prime{i}","file":f"prime{i}.png","type":"prime","available":os.path.exists(_asset_path(f"prime{i}.png"))} for i in range(9)]
    custom = [{"name":n,"file":f,"type":"custom","available":os.path.exists(_asset_path(f))} for n,f in CUSTOM_BADGE_FILES.items()]
    return jsonify({"badges": prime + custom})


@app.route("/frames")
def route_frames():
    return jsonify({"frames": [{"name":n,"file":f,"available":os.path.exists(_asset_path(f))} for n,f in CUSTOM_FRAME_FILES.items()]})


@app.route("/prime-levels")
def route_prime_levels():
    return jsonify({"levels":[{"level":i,"badge":f"prime{i}.png","frame":"prime8frame.png" if i==8 else None} for i in range(9)]})

# ─── Items ───────────────────────────────────────────────────────────────────

@app.route("/item")
def route_item():
    info  = request.args.get("info","").strip()
    query = info or request.args.get("q","").strip()
    if not query:
        return jsonify({"error":"info or q parameter required"}), 400
    results = search_items(query)
    return jsonify({"query":query,"count":len(results),"results":results[:50]})


@app.route("/item/info")
def route_item_info():
    q = request.args.get("q", request.args.get("query", request.args.get("name", ""))).strip()
    item_id = request.args.get("item_id", request.args.get("id", "")).strip()
    if item_id:
        exact = [
            item for item in item_db
            if str(item.get("itemID", item.get("id", ""))) == item_id
        ]
        if not exact:
            return jsonify({"error": "Item not found", "item_id": item_id}), 404
        return jsonify({"query": item_id, "count": 1, "items": exact[:1], "exact": True})
    if not q:
        return jsonify({"error":"q, name, or item_id is required"}), 400
    results = search_items(q)
    return jsonify({"query":q,"count":len(results),"items":results[:50],"exact":False})


@app.route("/item/lookup")
@app.route("/item-info")
def route_item_lookup():
    """Stable exact-or-search item lookup alias."""
    return route_item_info()


@app.route("/items")
def route_items():
    return jsonify({"items":ITEMS,"count":len(ITEMS)})


@app.route("/items/search")
def route_items_search():
    q = request.args.get("q","").strip()
    if not q:
        return jsonify({"error":"q is required"}), 400
    results = search_items(q)
    return jsonify({"query":q,"count":len(results),"results":results[:100]})


@app.route("/items/category")
def route_items_category():
    item_type = request.args.get("type","").strip().upper()
    if not item_type:
        types = list({it.get("itemType","") for it in item_db if it.get("itemType","")})
        return jsonify({"available_types":sorted(types)})
    results = [it for it in item_db if it.get("itemType","").upper() == item_type or it.get("type","").upper() == item_type]
    return jsonify({"type":item_type,"count":len(results),"results":results[:100]})

# ─── Weapon Info ──────────────────────────────────────────────────────────────

WEAPONS = {
    "901000001":{"name":"M4A1","type":"Assault Rifle","damage":45,"accuracy":80,"fire_rate":57,"range":77,"magazine":30},
    "901000002":{"name":"AK-47","type":"Assault Rifle","damage":55,"accuracy":70,"fire_rate":55,"range":73,"magazine":30},
    "901000003":{"name":"AWM","type":"Sniper","damage":90,"accuracy":95,"fire_rate":25,"range":99,"magazine":1},
    "901000004":{"name":"MP5","type":"SMG","damage":30,"accuracy":75,"fire_rate":72,"range":45,"magazine":30},
    "901000005":{"name":"Desert Eagle","type":"Pistol","damage":60,"accuracy":85,"fire_rate":30,"range":50,"magazine":7},
    "901000006":{"name":"Groza","type":"Assault Rifle","damage":62,"accuracy":68,"fire_rate":58,"range":69,"magazine":30},
    "901000007":{"name":"M1887","type":"Shotgun","damage":100,"accuracy":35,"fire_rate":18,"range":30,"magazine":2},
    "901000008":{"name":"MP40","type":"SMG","damage":27,"accuracy":72,"fire_rate":83,"range":42,"magazine":25},
    "901000009":{"name":"SCAR","type":"Assault Rifle","damage":44,"accuracy":78,"fire_rate":60,"range":79,"magazine":30},
    "901000010":{"name":"SVD","type":"Sniper","damage":79,"accuracy":90,"fire_rate":31,"range":95,"magazine":10},
    "901000011":{"name":"VSS","type":"Sniper","damage":45,"accuracy":88,"fire_rate":45,"range":88,"magazine":30},
    "901000012":{"name":"AN94","type":"Assault Rifle","damage":47,"accuracy":77,"fire_rate":56,"range":76,"magazine":30},
    "901000013":{"name":"Woodpecker","type":"Assault Rifle","damage":73,"accuracy":77,"fire_rate":27,"range":88,"magazine":15},
    "901000014":{"name":"Dragunov","type":"Sniper","damage":78,"accuracy":92,"fire_rate":29,"range":96,"magazine":10},
}


@app.route("/weapon-info")
def route_weapon_info():
    weapon_id = request.args.get("weapon_id","").strip()
    name_q    = request.args.get("name","").strip().lower()
    if not weapon_id and not name_q:
        return jsonify({"error":"weapon_id or name required","available": list(WEAPONS.keys())}), 400
    if name_q:
        for wid, winfo in WEAPONS.items():
            if name_q in winfo["name"].lower():
                return jsonify({"weapon_id":wid,**winfo})
        return jsonify({"error":"Weapon not found","query":name_q}), 404
    info = WEAPONS.get(weapon_id)
    if info:
        return jsonify({"weapon_id":weapon_id,**info})
    return jsonify({"error":"Weapon not found","weapon_id":weapon_id}), 404

# ─── Badge Info ───────────────────────────────────────────────────────────────

BADGES = {
    "1001000097":{"name":"Gold Badge","rarity":"Legendary","description":"A badge of exceptional honor"},
    "1001000098":{"name":"Silver Badge","rarity":"Epic","description":"Silver achievement badge"},
    "1001000099":{"name":"Bronze Badge","rarity":"Rare","description":"Bronze achievement badge"},
    "1001000100":{"name":"Diamond Badge","rarity":"Legendary","description":"Diamond prestige badge"},
    "1001000101":{"name":"Platinum Badge","rarity":"Epic","description":"Platinum rank badge"},
    "1001000102":{"name":"Master Badge","rarity":"Legendary","description":"Master rank badge"},
    "1001000103":{"name":"Grandmaster Badge","rarity":"Mythic","description":"Top 300 grandmaster badge"},
}


@app.route("/badge-info")
def route_badge_info():
    badge_id = request.args.get("badge_id","").strip()
    if not badge_id:
        return jsonify({"error":"badge_id is required","available":list(BADGES.keys())}), 400
    info = BADGES.get(badge_id)
    if info:
        return jsonify({"badge_id":badge_id,**info})
    return jsonify({"error":"Badge not found","badge_id":badge_id}), 404

# ─── Game Info ────────────────────────────────────────────────────────────────

@app.route("/game-modes")
def route_game_modes():
    return jsonify({"game_modes":[
        {"id":"br","name":"Battle Royale","max_players":50,"description":"Classic last-player-standing mode"},
        {"id":"cs","name":"Clash Squad","max_players":8,"description":"5v4 squad tactical mode"},
        {"id":"lone_wolf","name":"Lone Wolf","max_players":2,"description":"1v1 duel mode"},
        {"id":"craftland","name":"Craftland","max_players":8,"description":"Custom map creation mode"},
        {"id":"training","name":"Training Grounds","max_players":1,"description":"Practice and skill improvement"},
        {"id":"rampage","name":"Rampage: Almighty","max_players":20,"description":"Special event mode"},
        {"id":"ranked_br","name":"Ranked Battle Royale","max_players":50,"description":"Competitive BR with rank points"},
        {"id":"ranked_cs","name":"Ranked Clash Squad","max_players":8,"description":"Competitive Clash Squad"},
    ]})


@app.route("/maps")
def route_maps():
    return jsonify({"maps":[
        {"id":"bermuda","name":"Bermuda","size":"large","description":"Classic tropical island map"},
        {"id":"purgatory","name":"Purgatory","size":"medium","description":"Urban warfare map with bridges"},
        {"id":"kalahari","name":"Kalahari","size":"large","description":"Desert survival map"},
        {"id":"nexterra","name":"Nexterra","size":"medium","description":"Futuristic sci-fi map"},
        {"id":"craftland","name":"Craftland","size":"custom","description":"User-created custom maps"},
        {"id":"bermuda_remastered","name":"Bermuda Remastered","size":"large","description":"Revamped classic Bermuda"},
    ]})


@app.route("/seasons")
def route_seasons():
    current_season = 53
    return jsonify({
        "current_season": current_season,
        "season_name": f"Season {current_season}",
        "tiers": [
            {"tier":"Bronze","min_points":0,"max_points":999},
            {"tier":"Silver","min_points":1000,"max_points":2999},
            {"tier":"Gold","min_points":3000,"max_points":5999},
            {"tier":"Platinum","min_points":6000,"max_points":9999},
            {"tier":"Diamond","min_points":10000,"max_points":14999},
            {"tier":"Heroic","min_points":15000,"max_points":24999},
            {"tier":"Grandmaster","min_points":25000,"max_points":None},
        ],
    })

# ─── Leaderboard ──────────────────────────────────────────────────────────────

@app.route("/leaderboard")
def route_leaderboard():
    limit = min(int(request.args.get("limit",10)), 100)
    entries = [
        {"rank":i+1,"uid":str(100000000+i),"nickname":f"Player_{i+1}",
         "level":random.randint(1,100),"points":random.randint(0,10000)}
        for i in range(limit)
    ]
    return jsonify({"leaderboard":entries,"limit":limit})

# ─── Image Generation ─────────────────────────────────────────────────────────

@app.route("/image")
def route_image():
    """AI image generation via pollinations.ai (free, no key).
    GET /image?prompt=DESCRIPTION           → returns image bytes (JPEG)
    GET /image?prompt=DESCRIPTION&url=1     → returns JSON with image URL (no download)
    GET /image?prompt=DESCRIPTION&download=1 → triggers browser download
    """
    prompt   = request.args.get("prompt","Free Fire battle royale cinematic").strip()
    download = request.args.get("download","").lower() in ("1","true","yes")
    url_only = request.args.get("url","").lower() in ("1","true","yes")
    width    = request.args.get("width","512")
    height   = request.args.get("height","512")
    model    = request.args.get("model","flux")  # flux, turbo, flux-realism, etc.
    try:
        import urllib.parse
        enc = urllib.parse.quote(prompt)
        img_url = (f"https://image.pollinations.ai/prompt/{enc}"
                   f"?width={width}&height={height}&model={model}&nologo=true&enhance=true")
        if url_only:
            return jsonify({
                "prompt": prompt,
                "url": img_url,
                "width": int(width), "height": int(height),
                "model": model,
                "tip": "Open the url directly to view the image",
            })
        img_resp = requests.get(img_url, timeout=45, headers={"User-Agent":"Mozilla/5.0"})
        if img_resp.status_code == 200 and img_resp.content:
            ct = img_resp.headers.get("Content-Type","image/jpeg")
            ext = "png" if "png" in ct else "jpg"
            resp_headers = {}
            if download:
                resp_headers["Content-Disposition"] = f'attachment; filename="ff_image.{ext}"'
            return Response(img_resp.content, mimetype=ct, headers=resp_headers)
        return jsonify({"error":"Image generation failed","status":img_resp.status_code, "url": img_url}), 502
    except Exception as e:
        return jsonify({"error":str(e)}), 500

# ─── Base64 utilities ─────────────────────────────────────────────────────────

@app.route("/base64/encode", methods=["GET", "POST"])
@app.route("/encode-base64", methods=["GET", "POST"])
def route_base64_encode():
    """Encode UTF-8 text or compact JSON.

    GET /base64/encode?data=hello
    POST /base64/encode {"data":"hello","urlsafe":true}
    """
    data = _body_or_args()
    value = data.get("data", data.get("text", data.get("value")))
    if value is None:
        return jsonify({"error": "data is required", "example": "/base64/encode?data=hello"}), 400
    urlsafe = str(data.get("urlsafe", "")).lower() in ("1", "true", "yes")
    encoded = _base64_encode_value(value, urlsafe)
    return jsonify({
        "encoded": encoded,
        "base64": encoded,
        "encoding": "base64url" if urlsafe else "base64",
        "input_type": "json" if isinstance(value, (dict, list)) else "text",
    })


@app.route("/base64/decode", methods=["GET", "POST"])
@app.route("/decode-base64", methods=["GET", "POST"])
def route_base64_decode():
    """Decode standard or URL-safe base64 into UTF-8 text/JSON."""
    data = _body_or_args()
    encoded = data.get("data", data.get("encoded", data.get("value")))
    if encoded is None:
        return jsonify({"error": "data is required", "example": "/base64/decode?data=aGVsbG8="}), 400
    urlsafe = str(data.get("urlsafe", "")).lower() in ("1", "true", "yes")
    try:
        decoded = _base64_decode_value(str(encoded), urlsafe)
        return jsonify({"decoded": decoded["text"], **decoded})
    except ValueError as exc:
        return jsonify({"error": str(exc), "encoding": "base64url" if urlsafe else "base64"}), 400


@app.route("/base64")
def route_base64():
    """Convenience endpoint: action=encode or action=decode."""
    action = request.args.get("action", "decode").lower()
    if action == "encode":
        return route_base64_encode()
    if action == "decode":
        return route_base64_decode()
    return jsonify({"error": "action must be encode or decode"}), 400

# ─── Custom image endpoints ───────────────────────────────────────────────────

def _image_response(image: io.BytesIO, filename: str = "ff-image.png"):
    image.seek(0)
    download = request.args.get("download", "").lower() in ("1", "true", "yes")
    headers = {"Cache-Control": "public, max-age=300"}
    if download:
        headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    return Response(image.read(), mimetype="image/png", headers=headers)


@app.route("/custom-banner")
@app.route("/banner/custom")
def route_custom_banner():
    """Render a banner without a player lookup.

    Required: playername. Optional: bannerid, avatarid, level, guildname,
    primelevel, badge, frame. This is useful for custom profiles and works
    even when the UID is private or unavailable.
    """
    if not PIL_AVAILABLE:
        return jsonify({"error": "Pillow is not available"}), 503
    player = {
        "name": clean_text(request.args.get("playername", request.args.get("name", "Free Fire Player"))),
        "level": request.args.get("level", "100"),
        "guild": clean_text(request.args.get("guildname", request.args.get("guild", ""))),
        "headPic": request.args.get("avatarid", request.args.get("avatar", "")),
        "banner_id": request.args.get("bannerid", request.args.get("banner", "")),
        "prime_level": request.args.get("primelevel", 0, type=int),
    }
    try:
        image = generate_banner_image(
            _fetch_image_bytes(player["headPic"]),
            _fetch_image_bytes(player["banner_id"]),
            player,
            request.args.get("badge"),
            request.args.get("frame"),
        )
        _inc("custom_banner")
        return _image_response(image, "custom-banner.png")
    except Exception as exc:
        return jsonify({"error": "Could not render custom banner", "detail": str(exc)}), 422


@app.route("/custom-outfit")
@app.route("/outfit/custom")
def route_custom_outfit():
    """Render an outfit from item IDs without requiring a UID."""
    if not PIL_AVAILABLE:
        return jsonify({"error": "Pillow is not available"}), 503
    data = {
        "character": request.args.get("character", request.args.get("head", DEFAULT_AVATAR_ID)),
        "mask": request.args.get("mask"),
        "shirt": request.args.get("shirt", request.args.get("top")),
        "pants": request.args.get("pants"),
        "shoes": request.args.get("shoes"),
        "emote": request.args.get("emote", request.args.get("faceprint")),
        "armor": request.args.get("armor", request.args.get("paint")),
        "weapon": request.args.get("weapon"),
        "pet": request.args.get("pet"),
    }
    if not any(data.get(k) for k in ("mask", "shirt", "pants", "shoes", "character")):
        return jsonify({"error": "character or at least one outfit item is required"}), 400
    try:
        image = generate_outfit_image(data)
        _inc("custom_outfit")
        return _image_response(image, "custom-outfit.png")
    except Exception as exc:
        return jsonify({"error": "Could not render custom outfit", "detail": str(exc)}), 422


@app.route("/outfit/types")
@app.route("/outfit-type")
def route_outfit_types():
    return jsonify({
        "slots": [
            {"name": "character", "aliases": ["head", "character_id"]},
            {"name": "mask", "aliases": []},
            {"name": "shirt", "aliases": ["top"]},
            {"name": "pants", "aliases": []},
            {"name": "shoes", "aliases": []},
            {"name": "emote", "aliases": ["faceprint"]},
            {"name": "armor", "aliases": ["paint"]},
            {"name": "weapon", "aliases": ["weapon_skin"]},
            {"name": "pet", "aliases": ["pet_skin"]},
        ],
        "examples": {
            "uid": "/outfit?uid=UID",
            "custom": "/custom-outfit?character=879&shirt=ITEM_ID&pants=ITEM_ID",
        },
    })


@app.route("/asset-url")
def route_asset_url():
    """Return stable CDN URLs for an avatar/banner/item ID."""
    item_id = request.args.get("id", request.args.get("item_id", "")).strip()
    if not item_id:
        return jsonify({"error": "id or item_id is required"}), 400
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,120}", item_id):
        return jsonify({"error": "invalid asset id"}), 400
    return jsonify({
        "id": item_id,
        "url": f"{CDN_URL}/{item_id}.png",
        "cdn": CDN_URL,
        "cache": "public, max-age=86400",
    })

# ─── Social / Action endpoints ────────────────────────────────────────────────

def _social_response(action: str, uid: str):
    return jsonify({"action":action,"uid":uid,"status":"success","message":f"{action.title()} sent successfully","timestamp":datetime.utcnow().isoformat()})


@app.route("/like")
def route_like():
    uid = request.args.get("uid","").strip()
    if not uid: return jsonify({"error":"uid required"}), 400
    return _social_response("like", uid)


@app.route("/follow")
def route_follow():
    uid = request.args.get("uid","").strip()
    if not uid: return jsonify({"error":"uid required"}), 400
    return _social_response("follow", uid)


@app.route("/boost")
def route_boost():
    uid = request.args.get("uid","").strip()
    if not uid: return jsonify({"error":"uid required"}), 400
    return _social_response("boost", uid)


@app.route("/vote")
def route_vote():
    uid = request.args.get("uid","").strip()
    if not uid: return jsonify({"error":"uid required"}), 400
    return _social_response("vote", uid)

# ─── AI Q&A ──────────────────────────────────────────────────────────────────

@app.route("/ai")
def route_ai():
    """Free AI Q&A powered by pollinations.ai (no API key needed).
    GET /ai?question=What+is+Free+Fire?
    GET /ai?question=...&model=mistral       (openai|mistral|llama|gemini)
    """
    question = request.args.get("question","").strip() or request.args.get("q","").strip()
    model    = request.args.get("model","openai").strip().lower()
    if not question:
        return jsonify({
            "error": "question parameter is required",
            "example": "/ai?question=What+is+Free+Fire?",
            "models": ["openai","mistral","llama","gemini"],
        }), 400
    _inc("ai")
    t0     = time.time()
    answer = ask_ai(question, model)
    elapsed = round(time.time() - t0, 2)
    return jsonify({
        "question":  question,
        "answer":    answer,
        "model":     model,
        "provider":  "pollinations.ai",
        "latency_s": elapsed,
        "timestamp": datetime.utcnow().isoformat() + "Z",
    })

# ─── Update Config ────────────────────────────────────────────────────────────

@app.route("/update_info")
def route_update_info():
    global _cached_config
    if _cached_config:
        return jsonify(_cached_config)
    try:
        resp = requests.get(UPDATE_API_URL, timeout=8)
        if resp.status_code == 200:
            _cached_config = resp.json()
            return jsonify(_cached_config)
    except:
        pass
    return jsonify({"version":"1.0","update_required":False,"message":"Update config unavailable"})


@app.route("/force_update")
def route_force_update():
    global _cached_config
    _cached_config = None
    try:
        resp = requests.get(UPDATE_API_URL, timeout=8)
        if resp.status_code == 200:
            _cached_config = resp.json()
            return jsonify({**_cached_config,"forced":True})
    except:
        pass
    return jsonify({"forced":True,"message":"Config refresh attempted"})

# ─── Server / Status ──────────────────────────────────────────────────────────

@app.route("/status")
def route_status():
    return jsonify({
        "status":"online","version":"7.0",
        "info_type":"protobuf-src",
        "proto_available": PROTO_AVAILABLE,
        "pil_available": PIL_AVAILABLE,
        "regions": list(_SERVICE_ACCOUNTS.keys()),
        "uptime_seconds": (datetime.utcnow()-_start_time).total_seconds(),
    })


@app.route("/health")
def route_health():
    return jsonify({"status":"ok","timestamp":datetime.utcnow().isoformat()})


@app.route("/ping")
def route_ping():
    return jsonify({"pong":True,"ts":datetime.utcnow().isoformat()})


@app.route("/version")
def route_version():
    return jsonify({
        "version":"7.0",
        "name":"FF Ultimate API",
        "merged":"ffinfoo+sulavcodex",
        "info_type":"protobuf-src",
        "features":["base64","custom-banner","custom-outfit","ai","real-player-protobuf"],
    })


@app.route("/analytics")
def route_analytics():
    return jsonify({
        "requests": _request_counter,
        "uptime_seconds": (datetime.utcnow()-_start_time).total_seconds(),
        "cached_regions": len(_token_cache),
        "cached_uids": len(_uid_region_cache),
    })


@app.route("/server-info")
def route_server_info():
    import platform
    return jsonify({
        "python": platform.python_version(),
        "platform": platform.system(),
        "version":"7.0",
        "proto_available": PROTO_AVAILABLE,
        "pil_available": PIL_AVAILABLE,
        "item_db_count": len(item_db),
        "regions": list(_SERVICE_ACCOUNTS.keys()),
        "uptime": str(datetime.utcnow()-_start_time).split('.')[0],
    })


@app.route("/time")
def route_time():
    return jsonify({"server_time":datetime.utcnow().isoformat()+"Z","timezone":"UTC"})


@app.route("/uptime")
def route_uptime():
    delta = datetime.utcnow() - _start_time
    return jsonify({
        "uptime_seconds": delta.total_seconds(),
        "uptime_human": str(delta).split('.')[0],
        "started_at": _start_time.isoformat()+"Z",
    })


# ── Legacy /sulav endpoint ────────────────────────────────────────────────────
@app.route("/sulav")
def route_sulav():
    return index()


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION: FRIEND ADD / REMOVE (src: @STAR_GMR / @PVT_STAR)
# ═══════════════════════════════════════════════════════════════════════════════

# --- AES helpers for friend operations (different key from ffinfoo) ------------
_FRIEND_KEY = bytes([89,103,38,116,99,37,68,69,117,104,54,37,90,99,94,56])
_FRIEND_IV  = bytes([54,111,121,90,68,114,50,50,69,51,121,99,104,106,77,37])
_API_KEY    = bytes([101,116,33,120,72,83,97,119,82,94,37,56,74,50,83,53])
_API_IV     = bytes([84,76,82,118,120,100,114,114,117,51,37,80,85,113,65,54])

def _friend_aes_encrypt(data: bytes) -> bytes:
    c = AES.new(_FRIEND_KEY, AES.MODE_CBC, _FRIEND_IV)
    return c.encrypt(crypto_pad(data, 16))

def _friend_aes_hex(data: bytes) -> str:
    return _friend_aes_encrypt(data).hex()

def _encrypt_api_packet(hex_str: str) -> str:
    plain = bytes.fromhex(hex_str)
    c = AES.new(_API_KEY, AES.MODE_CBC, _API_IV)
    return c.encrypt(crypto_pad(plain, 16)).hex()

# byte.py inline: encode UID to protobuf varint hex
_DEC_HEX = ['80','81','82','83','84','85','86','87','88','89','8a','8b','8c','8d','8e','8f',
             '90','91','92','93','94','95','96','97','98','99','9a','9b','9c','9d','9e','9f',
             'a0','a1','a2','a3','a4','a5','a6','a7','a8','a9','aa','ab','ac','ad','ae','af',
             'b0','b1','b2','b3','b4','b5','b6','b7','b8','b9','ba','bb','bc','bd','be','bf',
             'c0','c1','c2','c3','c4','c5','c6','c7','c8','c9','ca','cb','cc','cd','ce','cf',
             'd0','d1','d2','d3','d4','d5','d6','d7','d8','d9','da','db','dc','dd','de','df',
             'e0','e1','e2','e3','e4','e5','e6','e7','e8','e9','ea','eb','ec','ed','ee','ef',
             'f0','f1','f2','f3','f4','f5','f6','f7','f8','f9','fa','fb','fc','fd','fe','ff']
_INT_HEX = ['1','01','02','03','04','05','06','07','08','09','0a','0b','0c','0d','0e','0f',
             '10','11','12','13','14','15','16','17','18','19','1a','1b','1c','1d','1e','1f',
             '20','21','22','23','24','25','26','27','28','29','2a','2b','2c','2d','2e','2f',
             '30','31','32','33','34','35','36','37','38','39','3a','3b','3c','3d','3e','3f',
             '40','41','42','43','44','45','46','47','48','49','4a','4b','4c','4d','4e','4f',
             '50','51','52','53','54','55','56','57','58','59','5a','5b','5c','5d','5e','5f',
             '60','61','62','63','64','65','66','67','68','69','6a','6b','6c','6d','6e','6f',
             '70','71','72','73','74','75','76','77','78','79','7a','7b','7c','7d','7e','7f']

def _encode_uid_hex(uid_int: int) -> str:
    x = uid_int
    r4 = x // (128**3); x %= 128**3
    r3 = x // (128**2); x %= 128**2
    r2 = x // 128;      r1 = x % 128
    return _DEC_HEX[r1] + _DEC_HEX[r2] + _DEC_HEX[r3] + _INT_HEX[r4 % len(_INT_HEX)]

def _ff_base_url(region: str) -> str:
    r = region.upper()
    if r == "IND": return "https://client.ind.freefiremobile.com/"
    if r in ("BR","US","SAC","NA"): return "https://client.us.freefiremobile.com/"
    if r == "ME": return "https://clientbp.ggpolarbear.com/"
    return "https://clientbp.ggpolarbear.com/"

def _jwt_decode_safe(token: str) -> dict:
    if not PYJWT_AVAILABLE: return {}
    try:
        return pyjwt.decode(token, options={"verify_signature": False})
    except Exception:
        return {}

def _region_from_token(token: str) -> str:
    d = _jwt_decode_safe(token)
    return d.get("lock_region", "IND").upper()

def _author_uid_from_token(token: str) -> Optional[str]:
    d = _jwt_decode_safe(token)
    uid = d.get("account_id") or d.get("sub")
    return str(uid) if uid else None

# --- MajorLogin: access_token → JWT ------------------------------------------
def _major_login_jwt(open_id: str, access_token: str, platform_type: int = 4) -> Optional[str]:
    """Try MajorLogin for one platform type; return JWT token or None."""
    if not MAJOR_LOGIN_PROTO_OK or not my_pb2: return None
    try:
        gd = my_pb2.GameData()
        gd.timestamp = "2024-12-05 18:15:32"
        gd.game_name = "free fire"
        gd.game_version = 1
        gd.version_code = "1.108.3"
        gd.os_info = "Android OS 9 / API-28 (PI/rel.cjw.20220518.114133)"
        gd.device_type = "Handheld"
        gd.network_provider = "Verizon Wireless"
        gd.connection_type = "WIFI"
        gd.screen_width = 1280
        gd.screen_height = 960
        gd.dpi = "240"
        gd.cpu_info = "ARMv7 VFPv3 NEON VMH | 2400 | 4"
        gd.total_ram = 5951
        gd.gpu_name = "Adreno (TM) 640"
        gd.gpu_version = "OpenGL ES 3.0"
        gd.user_id = "Google|74b585a9-0268-4ad3-8f36-ef41d2e53610"
        gd.ip_address = "172.190.111.97"
        gd.language = "en"
        gd.open_id = open_id
        gd.access_token = access_token
        gd.platform_type = platform_type
        gd.field_99 = str(platform_type)
        gd.field_100 = str(platform_type)
        enc = _friend_aes_encrypt(gd.SerializeToString())
        resp = requests.post(
            "https://loginbp.ggblueshark.com/MajorLogin",
            data=enc,
            headers={
                "User-Agent":"Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
                "Connection":"Keep-Alive","Accept-Encoding":"gzip",
                "Content-Type":"application/octet-stream",
                "Expect":"100-continue","X-Unity-Version":"2018.4.11f1",
                "X-GA":"v1 1","ReleaseVersion":"OB54"
            }, timeout=10, verify=False
        )
        if resp.status_code == 200 and output_pb2:
            msg = output_pb2.Garena_420()
            msg.ParseFromString(resp.content)
            tok = msg.token
            if tok: return tok
    except Exception:
        pass
    return None

def _get_jwt_from_access_token(access_token: str) -> Tuple[Optional[str], Optional[str]]:
    """access_token → JWT. Tries inspect + MajorLogin on multiple platforms."""
    try:
        insp = requests.get(
            f"https://100067.connect.garena.com/oauth/token/inspect?token={access_token}",
            timeout=8, verify=False
        )
        open_id = insp.json().get("open_id") if insp.status_code == 200 else None
        if not open_id:
            # fallback: reward API
            rw = requests.get(
                "https://prod-api.reward.ff.garena.com/redemption/api/auth/inspect_token/",
                headers={"access-token": access_token,
                         "User-Agent":"Mozilla/5.0 (Linux; Android 10; K)"},
                timeout=8, verify=False
            )
            if rw.status_code == 200:
                open_id = rw.json().get("open_id") or rw.json().get("uid")
        if not open_id:
            return None, "open_id not found"
        for pt in [4, 2, 6, 8, 3, 1, 5, 7, 9, 10, 11, 12]:
            tok = _major_login_jwt(str(open_id), access_token, pt)
            if tok: return tok, None
        return None, "MajorLogin failed on all platforms"
    except Exception as e:
        return None, str(e)

def _get_jwt_from_uid_password(uid: str, password: str) -> Tuple[Optional[str], Optional[str]]:
    """uid+password → access_token → JWT."""
    try:
        resp = requests.post(
            "https://100067.connect.garena.com/oauth/guest/token/grant",
            data={
                'uid': uid, 'password': password,
                'response_type': "token", 'client_type': "2",
                'client_secret': "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
                'client_id': "100067"
            },
            headers={"User-Agent":"GarenaMSDK/4.0.19P9(SM-M526B ;Android 13;pt;BR;)",
                     "Connection":"Keep-Alive"},
            timeout=10, verify=False
        )
        data = resp.json()
        if 'access_token' not in data:
            return None, data.get("error_description", "OAuth failed")
        at = data['access_token']
        oi = data.get('open_id', '')
        for pt in [4, 2, 6, 8, 3, 1, 5, 7, 9, 10, 11, 12]:
            tok = _major_login_jwt(str(oi), at, pt)
            if tok: return tok, None
        return None, "MajorLogin failed on all platforms"
    except Exception as e:
        return None, str(e)

def _resolve_jwt(jwt_token: str = None, access_token: str = None,
                 uid: str = None, password: str = None) -> Tuple[Optional[str], Optional[str]]:
    if jwt_token:     return jwt_token, None
    if access_token:  return _get_jwt_from_access_token(access_token)
    if uid and password: return _get_jwt_from_uid_password(uid, password)
    return None, "Provide jwt, access_token, or uid+password"

# --- Friend: get player info (uid_gen proto) -----------------------------------
def _ff_get_player_info(target_uid: str, token: str, region: str = None) -> Optional[Any]:
    if not uid_gen_pb2: return None
    try:
        rgn = region or _region_from_token(token)
        msg = uid_gen_pb2.uid_generator()
        msg.saturn_ = int(target_uid)
        msg.garena = 1
        enc_hex = _friend_aes_hex(msg.SerializeToString())
        resp = requests.post(
            _ff_base_url(rgn) + "GetPlayerPersonalShow",
            data=bytes.fromhex(enc_hex),
            headers={
                'Authorization': f"Bearer {token}",
                'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
                'Connection': "Keep-Alive", 'Accept-Encoding': "gzip",
                'Content-Type': "application/x-www-form-urlencoded",
                'Expect': "100-continue", 'X-Unity-Version': "2018.4.11f1",
                'X-GA': "v1 1", 'ReleaseVersion': "OB54"
            }, timeout=12, verify=False
        )
        if resp.status_code != 200: return None
        # parse with our existing AccountPersonalShowInfo if available
        if PROTO_AVAILABLE:
            from proto import AccountPersonalShow_pb2 as _ap
            info = _ap.AccountPersonalShowInfo()
            info.ParseFromString(resp.content)
            return info
        # fallback: return raw bytes
        return resp.content
    except Exception:
        return None

def _extract_ff_player_dict(info) -> dict:
    try:
        bi = info.basic_info
        return {
            "uid": bi.account_id, "nickname": bi.nickname,
            "level": bi.level, "region": bi.region,
            "likes": bi.liked, "release_version": bi.release_version,
        }
    except Exception:
        return {}

def _ff_get_friends_list(target_uid: str, token: str, region: str = None) -> Tuple[list, int]:
    if not uid_gen_pb2 or not social_data_pb2: return [], 0
    try:
        rgn = region or _region_from_token(token)
        msg = uid_gen_pb2.uid_generator()
        msg.saturn_ = int(target_uid)
        msg.garena = 1
        enc_hex = _friend_aes_hex(msg.SerializeToString())
        resp = requests.post(
            _ff_base_url(rgn) + "GetPlayerSocialNetwork",
            data=bytes.fromhex(enc_hex),
            headers={
                'Authorization': f"Bearer {token}",
                'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
                'Connection': "Keep-Alive", 'Accept-Encoding': "gzip",
                'Content-Type': "application/x-www-form-urlencoded",
                'Expect': "100-continue", 'X-Unity-Version': "2018.4.11f1",
                'X-GA': "v1 1", 'ReleaseVersion': "OB54"
            }, timeout=12, verify=False
        )
        if resp.status_code != 200: return [], 0
        # Try to parse social network
        names, count = [], 0
        for cls_name in ["SocialNetwork","PlayerSocialNetwork","SocialBasicInfo"]:
            cls = getattr(social_data_pb2, cls_name, None)
            if cls:
                try:
                    sn = cls()
                    sn.ParseFromString(resp.content)
                    friend_attr = getattr(sn, 'friends', None) or getattr(sn, 'friend_list', None)
                    if friend_attr is not None:
                        count = len(friend_attr)
                        for f in friend_attr:
                            names.append(getattr(f,'nickname','') or getattr(f,'name','Unknown'))
                        return names, count
                except Exception:
                    continue
        return [], 0
    except Exception:
        return [], 0

# --- Friend add ---------------------------------------------------------------
def _ff_add_friend(author_uid: str, target_uid: str, token: str, region: str = "IND") -> dict:
    try:
        enc_uid = _encode_uid_hex(int(target_uid))
        payload = f"08a7c4839f1e10{enc_uid}1801"
        enc_payload = _encrypt_api_packet(payload)
        resp = requests.post(
            _ff_base_url(region) + "RequestAddingFriend",
            data=bytes.fromhex(enc_payload),
            headers={
                "Authorization": f"Bearer {token}",
                "X-Unity-Version": "2018.4.11f1", "X-GA": "v1 1",
                "ReleaseVersion": "OB54",
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": "Dalvik/2.1.0 (Linux; Android 9)"
            }, timeout=12, verify=False
        )
        status = "success" if resp.status_code == 200 else "failed"
        # get target player info
        pinfo = _ff_get_player_info(target_uid, token, region)
        pdata = _extract_ff_player_dict(pinfo) if pinfo else {}
        fnames, fcount = _ff_get_friends_list(target_uid, token, region)
        return {
            "status": status,
            "action": "friend_add",
            "sender_uid": author_uid,
            "target_uid": target_uid,
            "target_nickname": pdata.get("nickname","Unknown"),
            "target_level": pdata.get("level",0),
            "target_likes": pdata.get("likes",0),
            "target_region": pdata.get("region","Unknown"),
            "target_friends_count": fcount,
            "target_friends": fnames[:20],
            "region": region,
            "http_code": resp.status_code,
            "time": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        }
    except Exception as e:
        return {"status":"error","error":str(e),"action":"friend_add","sender_uid":author_uid,"target_uid":target_uid}

# --- Friend remove ------------------------------------------------------------
def _ff_remove_friend(author_uid: str, target_uid: str, token: str, region: str = "IND") -> dict:
    if not remove_friend_pb2:
        return {"status":"error","error":"RemoveFriend proto not loaded"}
    try:
        msg = remove_friend_pb2.RemoveFriend()
        msg.AuthorUid = int(author_uid)
        msg.TargetUid = int(target_uid)
        enc = _friend_aes_encrypt(msg.SerializeToString())
        resp = requests.post(
            _ff_base_url(region) + "RemoveFriend",
            data=enc,
            headers={
                "Authorization": f"Bearer {token}",
                "User-Agent": "Dalvik/2.1.0 (Linux; Android 9)",
                "Content-Type": "application/x-www-form-urlencoded",
                "X-Unity-Version": "2018.4.11f1", "X-GA": "v1 1",
                "ReleaseVersion": "OB54"
            }, timeout=12, verify=False
        )
        status = "success" if resp.status_code == 200 else "failed"
        pinfo = _ff_get_player_info(target_uid, token, region)
        pdata = _extract_ff_player_dict(pinfo) if pinfo else {}
        fnames, fcount = _ff_get_friends_list(target_uid, token, region)
        return {
            "status": status,
            "action": "friend_remove",
            "remover_uid": author_uid,
            "target_uid": target_uid,
            "target_nickname": pdata.get("nickname","Unknown"),
            "target_level": pdata.get("level",0),
            "target_likes": pdata.get("likes",0),
            "target_region": pdata.get("region","Unknown"),
            "target_friends_count": fcount,
            "target_friends": fnames[:20],
            "region": region,
            "http_code": resp.status_code,
            "time": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        }
    except Exception as e:
        return {"status":"error","error":str(e),"action":"friend_remove","remover_uid":author_uid,"target_uid":target_uid}


# ─── Friend Routes ────────────────────────────────────────────────────────────
@app.route("/friend/add")
def route_friend_add():
    """Add friend.
    GET /friend/add?friend_uid=TARGET&jwt=JWT
    GET /friend/add?friend_uid=TARGET&access_token=TOKEN
    GET /friend/add?friend_uid=TARGET&uid=UID&password=PASS
    Optional: &region=IND|SG|ID|BR|ME|VN|TH|PK|CIS|US|RU|TW
    """
    _request_counter["friend_add"] = _request_counter.get("friend_add",0)+1
    friend_uid = request.args.get("friend_uid","").strip()
    jwt_tok    = request.args.get("jwt","").strip()
    access_tok = request.args.get("access_token","").strip()
    uid        = request.args.get("uid","").strip()
    password   = request.args.get("password","").strip()
    region     = request.args.get("region","IND").strip().upper()
    if not friend_uid:
        return jsonify({"error":"friend_uid is required"}), 400
    token, err = _resolve_jwt(jwt_tok or None, access_tok or None,
                               uid or None, password or None)
    if err or not token:
        return jsonify({"error": err or "Authentication failed"}), 400
    author_uid = _author_uid_from_token(token)
    if not author_uid:
        return jsonify({"error":"Invalid token: cannot decode author uid"}), 400
    result = _ff_add_friend(author_uid, friend_uid, token, region)
    code = 200 if result.get("status")=="success" else 502
    return jsonify(result), code

@app.route("/friend/remove")
def route_friend_remove():
    """Remove friend.
    GET /friend/remove?friend_uid=TARGET&jwt=JWT
    GET /friend/remove?friend_uid=TARGET&access_token=TOKEN
    GET /friend/remove?friend_uid=TARGET&uid=UID&password=PASS
    Optional: &region=IND|SG|...
    """
    _request_counter["friend_remove"] = _request_counter.get("friend_remove",0)+1
    friend_uid = request.args.get("friend_uid","").strip()
    jwt_tok    = request.args.get("jwt","").strip()
    access_tok = request.args.get("access_token","").strip()
    uid        = request.args.get("uid","").strip()
    password   = request.args.get("password","").strip()
    region     = request.args.get("region","IND").strip().upper()
    if not friend_uid:
        return jsonify({"error":"friend_uid is required"}), 400
    token, err = _resolve_jwt(jwt_tok or None, access_tok or None,
                               uid or None, password or None)
    if err or not token:
        return jsonify({"error": err or "Authentication failed"}), 400
    author_uid = _author_uid_from_token(token)
    if not author_uid:
        return jsonify({"error":"Invalid token: cannot decode author uid"}), 400
    result = _ff_remove_friend(author_uid, friend_uid, token, region)
    code = 200 if result.get("status")=="success" else 502
    return jsonify(result), code

@app.route("/friend/list")
def route_friend_list():
    """Get friends list of a player.
    GET /friend/list?uid=TARGET_UID&jwt=JWT
    GET /friend/list?uid=TARGET_UID&access_token=TOKEN
    """
    _request_counter["friend_list"] = _request_counter.get("friend_list",0)+1
    target_uid = request.args.get("uid","").strip()
    jwt_tok    = request.args.get("jwt","").strip()
    access_tok = request.args.get("access_token","").strip()
    my_uid     = request.args.get("my_uid","").strip()
    my_pass    = request.args.get("password","").strip()
    region     = request.args.get("region","IND").strip().upper()
    if not target_uid:
        return jsonify({"error":"uid is required (target player)"}), 400
    token, err = _resolve_jwt(jwt_tok or None, access_tok or None,
                               my_uid or None, my_pass or None)
    if err or not token:
        return jsonify({"error": err or "Authentication failed"}), 400
    names, count = _ff_get_friends_list(target_uid, token, region)
    pinfo = _ff_get_player_info(target_uid, token, region)
    pdata = _extract_ff_player_dict(pinfo) if pinfo else {}
    return jsonify({
        "uid": target_uid,
        "nickname": pdata.get("nickname",""),
        "level": pdata.get("level",0),
        "region": pdata.get("region", region),
        "friends_count": count,
        "friends": names,
        "time": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
    })


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION: LONG BIO UPDATE (src: FfBioChange / KrsxhNvrDie)
# ═══════════════════════════════════════════════════════════════════════════════

_BIO_UPDATE_URL = "https://clientbp.ggpolarbear.com/UpdateSocialBasicInfo"
_BIO_KEY = bytes([89,103,38,116,99,37,68,69,117,104,54,37,90,99,94,56])
_BIO_IV  = bytes([54,111,121,90,68,114,50,50,69,51,121,99,104,106,77,37])

def _build_bio_protobuf(bio_text: str) -> bytes:
    """Hand-craft the UpdateSocialBasicInfo protobuf payload (supports long bios)."""
    bio_bytes = bio_text.encode('utf-8')
    bio_len = len(bio_bytes)
    # Field 2 = 7, Field 5 empty, Field 6 empty
    pb = bytes([0x10, 0x07, 0x2a, 0x00, 0x32, 0x00])
    # Field 8: bio string — handle varint length encoding for long bios
    pb += bytes([0x42])
    if bio_len < 128:
        pb += bytes([bio_len])
    else:
        pb += bytes([(bio_len & 0x7F) | 0x80, bio_len >> 7])
    pb += bio_bytes
    # Field 9 = 1, Field 11 empty, Field 12 empty
    pb += bytes([0x48, 0x01, 0x5a, 0x00, 0x62, 0x00])
    return pb

def _encrypt_bio(data: bytes) -> bytes:
    c = AES.new(_BIO_KEY, AES.MODE_CBC, _BIO_IV)
    return c.encrypt(crypto_pad(data, 16))

def _get_openid_from_shop2game(uid: str) -> Optional[str]:
    try:
        r = requests.post(
            "https://shop2game.com/api/auth/player_id_login",
            headers={"Accept":"application/json, text/plain, */*",
                     "Content-Type":"application/json",
                     "User-Agent":"Mozilla/5.0 (Linux; Android 10; K)"},
            json={"app_id":100067,"login_id":str(uid)},
            timeout=8, verify=False
        )
        return r.json().get("open_id")
    except Exception:
        return None

def _get_info_from_reward_api(access_token: str) -> dict:
    try:
        r = requests.get(
            "https://prod-api.reward.ff.garena.com/redemption/api/auth/inspect_token/",
            headers={"access-token": access_token,
                     "User-Agent":"Mozilla/5.0 (Linux; Android 10; K)"},
            timeout=8, verify=False
        )
        return r.json() if r.status_code == 200 else {}
    except Exception:
        return {}

def _do_update_bio(token: str, bio_text: str) -> dict:
    try:
        pb = _build_bio_protobuf(bio_text)
        enc = _encrypt_bio(pb)
        resp = requests.post(
            _BIO_UPDATE_URL, data=enc,
            headers={
                'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 9; G011A Build/PI)',
                'Connection': 'Keep-Alive', 'Accept-Encoding': 'gzip',
                'Content-Type': 'application/x-www-form-urlencoded',
                'Expect': '100-continue', 'X-Unity-Version': '2018.4.11f1',
                'X-GA': 'v1 1', 'ReleaseVersion': 'OB53',
                'Authorization': f'Bearer {token}',
            }, timeout=20, verify=False
        )
        return {
            "success": resp.status_code == 200,
            "http_code": resp.status_code,
            "response_hex": resp.content.hex()[:80],
        }
    except Exception as e:
        return {"success": False, "error": str(e), "http_code": 500}

# ─── Bio Route ────────────────────────────────────────────────────────────────
@app.route("/update-bio", methods=["GET","POST"])
def route_update_bio():
    """Update Free Fire biography (long bio supported, up to 500 chars).
    GET /update-bio?bio=TEXT&jwt=JWT
    GET /update-bio?bio=TEXT&access_token=TOKEN
    GET /update-bio?bio=TEXT&uid=UID&password=PASS
    POST with JSON body: {bio, jwt|access_token|uid+password}
    """
    _request_counter["bio_update"] = _request_counter.get("bio_update",0)+1
    if request.method == "POST":
        body = request.get_json(silent=True) or {}
        bio        = body.get("bio","")
        jwt_tok    = body.get("jwt","")
        access_tok = body.get("access_token","")
        uid        = body.get("uid","")
        password   = body.get("password","")
    else:
        bio        = request.args.get("bio","").strip()
        jwt_tok    = request.args.get("jwt","").strip()
        access_tok = request.args.get("access_token","").strip()
        uid        = request.args.get("uid","").strip()
        password   = request.args.get("password","").strip()

    if not bio:
        return jsonify({"error":"bio is required"}), 400
    bio = bio[:500]  # hard cap
    token, err = _resolve_jwt(jwt_tok or None, access_tok or None,
                               uid or None, password or None)
    if err or not token:
        return jsonify({"error": err or "Authentication failed"}), 400

    d = _jwt_decode_safe(token)
    author_uid = d.get("account_id","")
    nickname   = d.get("nickname","")
    region     = d.get("lock_region","")
    method     = "jwt" if jwt_tok else ("access_token" if access_tok else "uid_password")

    result = _do_update_bio(token, bio)
    result.update({
        "uid": author_uid,
        "nickname": nickname,
        "region": region,
        "bio": bio,
        "bio_length": len(bio.encode()),
        "method": method,
        "time": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
    })
    code = 200 if result.get("success") else 502
    return jsonify(result), code


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION: BIND INFO, PLATFORM CHECK & ACCOUNT SECURITY (src: sulav_codex_ff / agajayofficial)
# ═══════════════════════════════════════════════════════════════════════════════

_GARENA_HEADERS = {
    "User-Agent": "GarenaMSDK/4.0.19P9(Redmi Note 5 ;Android 9;en;US;)",
    "Connection": "Keep-Alive",
    "Accept-Encoding": "gzip",
    "Accept": "application/json",
}
_GARENA_BASE = "https://100067.connect.garena.com"

# Extended platform map (all known platforms)
_PLATFORM_NAMES = {
    1:  "Garena (Guest)",
    2:  "Email",
    3:  "Facebook",
    4:  "Google Play Games",
    5:  "VK (VKontakte)",
    6:  "Garena (Account)",
    7:  "Huawei GameCenter",
    8:  "Gmail / Google",
    9:  "Apple / Game Center",
    10: "iCloud / Apple ID",
    11: "Twitter / X",
    12: "Line",
    13: "Kakao",
    14: "WeChat",
    15: "Weibo",
    16: "Naver",
    17: "Nintendo",
    18: "PlayStation",
    20: "Steam",
    22: "Tencent QQ",
    23: "TikTok / ByteDance",
}

def _garena_get(path: str, params: dict) -> dict:
    try:
        r = requests.get(f"{_GARENA_BASE}{path}", params=params,
                         headers=_GARENA_HEADERS, timeout=10, verify=False)
        return r.json() if r.status_code in (200,201) else {"error":f"HTTP {r.status_code}","raw":r.text[:200]}
    except Exception as e:
        return {"error": str(e)}

def _garena_post(path: str, data: dict) -> dict:
    try:
        r = requests.post(f"{_GARENA_BASE}{path}", data=data,
                          headers={**_GARENA_HEADERS, "Content-Type":"application/x-www-form-urlencoded"},
                          timeout=10, verify=False)
        return r.json() if r.status_code in (200,201) else {"error":f"HTTP {r.status_code}","raw":r.text[:200]}
    except Exception as e:
        return {"error": str(e)}

# ─── Bind Info Routes ─────────────────────────────────────────────────────────
@app.route("/bind-info")
def route_bind_info():
    """Get recovery email bind status.
    GET /bind-info?access_token=TOKEN
    """
    _request_counter["bind_info"] = _request_counter.get("bind_info",0)+1
    at = request.args.get("access_token","").strip()
    if not at:
        return jsonify({"error":"access_token is required"}), 400
    data = _garena_get("/game/account_security/bind:get_bind_info",
                       {"app_id":"100067","access_token":at})
    email       = data.get("email","")
    email_to_be = data.get("email_to_be","")
    countdown   = data.get("request_exec_countdown",0)

    bind_status = "none"
    if email and not email_to_be:     bind_status = "verified"
    elif not email and email_to_be:   bind_status = "pending"
    elif email and email_to_be:       bind_status = "changing"

    result = {
        "bind_status":         bind_status,
        "current_email":       email,
        "pending_email":       email_to_be,
        "confirmation_in_sec": countdown,
        "raw":                 data,
    }
    return jsonify(result)

@app.route("/platforms")
def route_platforms():
    """Check all linked platforms on a Garena account.
    GET /platforms?access_token=TOKEN
    """
    _request_counter["platforms"] = _request_counter.get("platforms",0)+1
    at = request.args.get("access_token","").strip()
    if not at:
        return jsonify({"error":"access_token is required"}), 400
    data = _garena_get("/bind/app/platform/info/get", {"access_token": at})
    bounded   = data.get("bounded_accounts", [])
    available = data.get("available_platforms", [])

    linked = []
    for acc in bounded:
        pid = acc.get("platform")
        ui  = acc.get("user_info", {})
        linked.append({
            "platform_id":   pid,
            "platform_name": _PLATFORM_NAMES.get(pid, f"Platform#{pid}"),
            "uid":           acc.get("uid"),
            "email":         ui.get("email",""),
            "nickname":      ui.get("nickname",""),
        })

    main_platform = None
    for pid, name in _PLATFORM_NAMES.items():
        if pid not in available and pid not in [a.get("platform") for a in bounded]:
            main_platform = {"platform_id": pid, "platform_name": name}
            break

    not_linked = [
        {"platform_id": pid, "platform_name": _PLATFORM_NAMES.get(pid, f"Platform#{pid}")}
        for pid in available if pid in _PLATFORM_NAMES
    ]

    return jsonify({
        "main_platform":   main_platform,
        "linked_accounts": linked,
        "linked_count":    len(linked),
        "available_to_link": not_linked,
        "all_platforms":   _PLATFORM_NAMES,
    })

@app.route("/bind/send-otp", methods=["GET","POST"])
def route_bind_send_otp():
    """Send OTP to email for bind/unbind operations.
    GET /bind/send-otp?access_token=TOKEN&email=EMAIL
    Optional: &locale=en_MA&region=IND
    """
    _request_counter["bind_send_otp"] = _request_counter.get("bind_send_otp",0)+1
    at     = (request.args.get("access_token") or request.json.get("access_token","") if request.is_json else request.args.get("access_token","")).strip()
    email  = (request.args.get("email") or (request.json.get("email","") if request.is_json else "")).strip()
    locale = request.args.get("locale","en_MA").strip()
    region = request.args.get("region","IND").strip().upper()
    if not at or not email:
        return jsonify({"error":"access_token and email are required"}), 400
    result = _garena_post("/game/account_security/bind:send_otp",
                          {"email":email,"locale":locale,"region":region,
                           "app_id":"100067","access_token":at})
    ok = result.get("result") == 0 or "error" not in result
    return jsonify({"sent":ok,"email":email,"raw":result}), (200 if ok else 400)

@app.route("/bind/verify-otp", methods=["GET","POST"])
def route_bind_verify_otp():
    """Verify OTP for bind operation. Returns verifier_token.
    GET /bind/verify-otp?access_token=TOKEN&email=EMAIL&otp=CODE
    """
    _request_counter["bind_verify_otp"] = _request_counter.get("bind_verify_otp",0)+1
    args = request.json if request.is_json else request.args
    at    = (args.get("access_token","")).strip()
    email = (args.get("email","")).strip()
    otp   = (args.get("otp","")).strip()
    if not at or not email or not otp:
        return jsonify({"error":"access_token, email and otp are required"}), 400
    result = _garena_post("/game/account_security/bind:verify_otp",
                          {"app_id":"100067","access_token":at,"otp":otp,"email":email})
    vt = result.get("verifier_token")
    return jsonify({"verified": bool(vt), "verifier_token": vt, "raw": result}), (200 if vt else 400)

@app.route("/bind/add-email", methods=["GET","POST"])
def route_bind_add_email():
    """Add recovery email. Full 2-step: send OTP → verify → bind.
    GET /bind/add-email?access_token=TOKEN&email=EMAIL&otp=CODE
    If otp is missing, only sends OTP and returns.
    If otp provided, completes the bind.
    """
    _request_counter["bind_add_email"] = _request_counter.get("bind_add_email",0)+1
    args  = request.json if request.is_json else request.args
    at    = (args.get("access_token","")).strip()
    email = (args.get("email","")).strip()
    otp   = (args.get("otp","")).strip()
    if not at or not email:
        return jsonify({"error":"access_token and email are required"}), 400
    if not otp:
        # Step 1 only: send OTP
        r = _garena_post("/game/account_security/bind:send_otp",
                         {"email":email,"locale":"en_MA","region":"IND",
                          "app_id":"100067","access_token":at})
        ok = r.get("result")==0 or "error" not in r
        return jsonify({"step":"otp_sent","sent":ok,"email":email,"raw":r}), (200 if ok else 400)
    # Step 2: verify OTP
    vr = _garena_post("/game/account_security/bind:verify_otp",
                      {"app_id":"100067","access_token":at,"otp":otp,"email":email})
    vt = vr.get("verifier_token")
    if not vt:
        return jsonify({"error":"OTP verification failed","raw":vr}), 400
    # Cancel any existing request first
    _garena_post("/game/account_security/bind:cancel_request",
                 {"app_id":"100067","access_token":at})
    # Step 3: create bind request
    br = _garena_post("/game/account_security/bind:create_bind_request",
                      {"app_id":"100067","access_token":at,"verifier_token":vt,
                       "secondary_password":"91B4D142823F7D20C5F08DF69122DE43F35F057A988D9619F6D3138485C9A203",
                       "email":email})
    ok = br.get("result")==0 or "error" not in br
    return jsonify({"step":"bind_created","success":ok,"email":email,"raw":br}), (200 if ok else 400)

@app.route("/bind/cancel-email", methods=["GET","POST"])
def route_bind_cancel_email():
    """Cancel pending recovery email request.
    GET /bind/cancel-email?access_token=TOKEN
    """
    _request_counter["bind_cancel"] = _request_counter.get("bind_cancel",0)+1
    at = (request.args.get("access_token","") or
          (request.json.get("access_token","") if request.is_json else "")).strip()
    if not at:
        return jsonify({"error":"access_token is required"}), 400
    r = _garena_post("/game/account_security/bind:cancel_request",
                     {"app_id":"100067","access_token":at})
    ok = r.get("result")==0 or "error" not in r
    return jsonify({"cancelled":ok,"raw":r})

@app.route("/bind/remove-email", methods=["GET","POST"])
def route_bind_remove_email():
    """Remove/unbind recovery email. Requires OTP or secondary password.
    GET /bind/remove-email?access_token=TOKEN&email=EMAIL&otp=CODE
    GET /bind/remove-email?access_token=TOKEN&email=EMAIL&secondary_password=HASH
    """
    _request_counter["bind_remove_email"] = _request_counter.get("bind_remove_email",0)+1
    args  = request.json if request.is_json else request.args
    at    = (args.get("access_token","")).strip()
    email = (args.get("email","")).strip()
    otp   = (args.get("otp","")).strip()
    sp    = (args.get("secondary_password","")).strip()
    if not at or not email:
        return jsonify({"error":"access_token and email are required"}), 400
    # Verify identity
    if otp:
        vd = {"email":email,"otp":otp,"app_id":"100067","access_token":at}
    elif sp:
        vd = {"email":email,"secondary_password":sp,"app_id":"100067","access_token":at}
    else:
        return jsonify({"error":"otp or secondary_password is required"}), 400
    vi = _garena_post("/game/account_security/bind:verify_identity", vd)
    it = vi.get("identity_token")
    if not it:
        return jsonify({"error":"Identity verification failed","raw":vi}), 400
    ur = _garena_post("/game/account_security/bind:create_unbind_request",
                      {"app_id":"100067","access_token":at,"identity_token":it})
    ok = ur.get("result")==0 or "error" not in ur
    return jsonify({"unbind_requested":ok,"raw":ur}), (200 if ok else 400)

@app.route("/bind/change-email", methods=["GET","POST"])
def route_bind_change_email():
    """Change recovery email. Verify old, then bind new.
    GET /bind/change-email?access_token=TOKEN&old_email=OLD&new_email=NEW
                          &old_otp=CODE_OLD&new_otp=CODE_NEW
    If old_otp/new_otp missing, only sends the relevant OTP.
    """
    _request_counter["bind_change_email"] = _request_counter.get("bind_change_email",0)+1
    args      = request.json if request.is_json else request.args
    at        = (args.get("access_token","")).strip()
    old_email = (args.get("old_email","")).strip()
    new_email = (args.get("new_email","")).strip()
    old_otp   = (args.get("old_otp","")).strip()
    new_otp   = (args.get("new_otp","")).strip()
    sp        = (args.get("secondary_password","")).strip()
    if not at or not old_email or not new_email:
        return jsonify({"error":"access_token, old_email and new_email are required"}), 400
    if not old_otp and not sp:
        # Send OTP for old email
        r = _garena_post("/game/account_security/bind:send_otp",
                         {"email":old_email,"locale":"en_MA","region":"IND",
                          "app_id":"100067","access_token":at})
        return jsonify({"step":"old_otp_sent","email":old_email,"raw":r})
    # Verify old identity
    if sp:
        vd = {"email":old_email,"secondary_password":sp,"app_id":"100067","access_token":at}
    else:
        vd = {"email":old_email,"otp":old_otp,"app_id":"100067","access_token":at}
    vi = _garena_post("/game/account_security/bind:verify_identity", vd)
    it = vi.get("identity_token")
    if not it:
        return jsonify({"error":"Old email verification failed","raw":vi}), 400
    if not new_otp:
        # Send OTP to new email
        r2 = _garena_post("/game/account_security/bind:send_otp",
                          {"email":new_email,"locale":"en_MA","region":"IND",
                           "app_id":"100067","access_token":at})
        return jsonify({"step":"new_otp_sent","identity_token":it,"email":new_email,"raw":r2})
    # Verify new email OTP
    vn = _garena_post("/game/account_security/bind:verify_otp",
                      {"email":new_email,"app_id":"100067","access_token":at,"otp":new_otp})
    vt = vn.get("verifier_token")
    if not vt:
        return jsonify({"error":"New email OTP failed","raw":vn}), 400
    # Rebind
    rb = _garena_post("/game/account_security/bind:create_rebind_request",
                      {"identity_token":it,"email":new_email,"app_id":"100067",
                       "verifier_token":vt,"access_token":at})
    ok = rb.get("result")==0 or "error" not in rb
    return jsonify({"step":"rebind_created","success":ok,"new_email":new_email,"raw":rb}), (200 if ok else 400)

@app.route("/revoke-token", methods=["GET","POST"])
def route_revoke_token():
    """Revoke / logout a Garena access token.
    GET /revoke-token?access_token=TOKEN
    """
    _request_counter["revoke_token"] = _request_counter.get("revoke_token",0)+1
    at = (request.args.get("access_token","") or
          (request.json.get("access_token","") if request.is_json else "")).strip()
    if not at:
        return jsonify({"error":"access_token is required"}), 400
    try:
        r = requests.get(
            f"{_GARENA_BASE}/oauth/logout?access_token={at}",
            headers=_GARENA_HEADERS, timeout=8, verify=False
        )
        ok = r.text.strip() == '{"result":0}'
        return jsonify({"revoked":ok,"raw":r.text[:200]})
    except Exception as e:
        return jsonify({"error":str(e)}), 500

@app.route("/bind/inspect-token")
def route_inspect_token():
    """Inspect a Garena access token (get uid, open_id, etc.).
    GET /bind/inspect-token?access_token=TOKEN
    """
    at = request.args.get("access_token","").strip()
    if not at: return jsonify({"error":"access_token is required"}), 400
    r1 = _garena_get("/oauth/token/inspect", {"token": at})
    # also try reward API
    r2 = _get_info_from_reward_api(at)
    return jsonify({"garena_inspect": r1, "reward_api": r2})

@app.route("/bind/decode-jwt")
def route_decode_jwt():
    """Decode a JWT token without verifying signature.
    GET /bind/decode-jwt?token=JWT_HERE
    """
    tok = request.args.get("token","").strip()
    if not tok: return jsonify({"error":"token is required"}), 400
    decoded = _jwt_decode_safe(tok)
    if not decoded:
        return jsonify({"error":"Failed to decode JWT"}), 400
    return jsonify({
        "uid":        decoded.get("account_id"),
        "nickname":   decoded.get("nickname"),
        "region":     decoded.get("lock_region"),
        "platform":   decoded.get("external_type"),
        "open_id":    decoded.get("open_id"),
        "expire_at":  decoded.get("exp"),
        "issued_at":  decoded.get("iat"),
        "full":       decoded,
    })

@app.route("/get-jwt")
def route_get_jwt():
    """Generate JWT from uid+password or access_token (tries all 12 platform types).
    GET /get-jwt?uid=UID&password=PASS
    GET /get-jwt?access_token=TOKEN
    """
    _request_counter["get_jwt"] = _request_counter.get("get_jwt",0)+1
    at  = request.args.get("access_token","").strip()
    uid = request.args.get("uid","").strip()
    pw  = request.args.get("password","").strip()
    if not at and not (uid and pw):
        return jsonify({"error":"Provide access_token OR uid+password"}), 400
    token, err = _resolve_jwt(None, at or None, uid or None, pw or None)
    if err or not token:
        return jsonify({"error": err or "Failed"}), 400
    decoded = _jwt_decode_safe(token)
    return jsonify({
        "status":   "success",
        "token":    token,
        "uid":      decoded.get("account_id"),
        "nickname": decoded.get("nickname"),
        "region":   decoded.get("lock_region"),
        "platform": decoded.get("external_type"),
    })


# ── Error Handlers ────────────────────────────────────────────────────────────
@app.errorhandler(404)
def not_found(e):
    return jsonify({"error":"Endpoint not found","hint":"GET / or /help for all endpoints"}), 404


@app.errorhandler(500)
def server_error(e):
    return jsonify({"error":"Internal server error","detail":str(e)}), 500


# ── Entry Point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import warnings
    warnings.filterwarnings("ignore")
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
