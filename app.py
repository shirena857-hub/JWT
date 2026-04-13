from flask import Flask, request, jsonify
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import binascii
import requests
import my_pb2
import output_pb2
import jwt
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

AES_KEY = b'Yg&tc%DEuh6%Zc^8'
AES_IV = b'6oyZDr22E3ychjM%'

PLATFORM_MAP = {
    3: "Facebook",
    4: "Guest",
    5: "VK",
    6: "Huawei",
    8: "Google",
    11: "X (Twitter)",
    13: "AppleId",
}

def encrypt_message(plaintext):
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    padded_message = pad(plaintext, AES.block_size)
    return cipher.encrypt(padded_message)

def build_major_login(open_id: str, access_token: str, platform_type: int) -> bytes:
    """পুরনো my_pb2.GameData ব্যবহার করে রিকোয়েস্ট বিল্ড করা"""
    game_data = my_pb2.GameData()
    game_data.timestamp = "2024-12-05 18:15:32"
    game_data.game_name = "free fire"
    game_data.game_version = 1
    game_data.version_code = "1.123.1"
    game_data.os_info = "Android OS 9 / API-28 (PI/rel.cjw.20220518.114133)"
    game_data.device_type = "Handheld"
    game_data.network_provider = "Verizon Wireless"
    game_data.connection_type = "WIFI"
    game_data.screen_width = 1280
    game_data.screen_height = 960
    game_data.dpi = "240"
    game_data.cpu_info = "ARMv7 VFPv3 NEON VMH | 2400 | 4"
    game_data.total_ram = 5951
    game_data.gpu_name = "Adreno (TM) 640"
    game_data.gpu_version = "OpenGL ES 3.0"
    game_data.user_id = "Google|74b585a9-0268-4ad3-8f36-ef41d2e53610"
    game_data.ip_address = "172.190.111.97"
    game_data.language = "en"
    game_data.open_id = open_id
    game_data.access_token = access_token
    game_data.platform_type = platform_type
    game_data.field_99 = str(platform_type)
    game_data.field_100 = str(platform_type)
    return game_data.SerializeToString()

def try_major_login(open_id: str, access_token: str, platform_type: int):
    """একটি প্ল্যাটফর্ম দিয়ে MajorLogin চেষ্টা করে, সফল হলে JWT টোকেন রিটার্ন করে"""
    serialized_data = build_major_login(open_id, access_token, platform_type)
    encrypted_data = encrypt_message(serialized_data)

    url = "https://loginbp.ggpolarbear.com/MajorLogin"
    headers = {
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
        "Connection": "Keep-Alive",
        "Accept-Encoding": "gzip",
        "Content-Type": "application/octet-stream",
        "Expect": "100-continue",
        "X-Unity-Version": "2018.4.11f1",
        "X-GA": "v1 1",
        "ReleaseVersion": "OB53"
    }

    try:
        response = requests.post(url, data=encrypted_data, headers=headers, verify=False, timeout=5)
        if response.status_code == 200:
            example_msg = output_pb2.Garena_420()
            example_msg.ParseFromString(response.content)
            token_value = getattr(example_msg, "token", None)
            if token_value:
                return token_value
    except Exception:
        pass
    return None

@app.route('/')
def read_root():
    return """
    <div style="text-align: center; font-family: Arial, sans-serif; margin-top: 50px;">
        <h1 style="color: #2ecc71;">🎨 Free Fire Access Token & Uid Password To Jwt Token API is Running!</h1>
        <p><b>Credit:</b> @Flexbasei</p>
        <p><b>Powered By:</b> @spideerio_yt</p>
        <hr style="width: 50%; border: 1px solid #eee;">
        <h2 style="color: #7f8c8d;">Use <code>/access-jwt?access_token={YourToken}</code> or <code>/token?uid={UID}&password={Password}</code> endpoint to get data.</h2>
    </div>
    """

@app.route('/access-jwt', methods=['GET'])
def majorlogin_jwt():
    access_token = request.args.get('access_token')
    provided_open_id = request.args.get('open_id')

    if not access_token:
        return jsonify({"message": "missing access_token"}), 400

    # যদি open_id সরাসরি দেওয়া না থাকে, তাহলে inspect API থেকে বের করো
    if not provided_open_id:
        try:
            inspect_url = f"https://100067.connect.garena.com/oauth/token/inspect?token={access_token}"
            insp_resp = requests.get(inspect_url, timeout=10)
            if insp_resp.status_code != 200:
                return jsonify({"message": "Invalid token or inspect API failed"}), 400
            insp_data = insp_resp.json()
            open_id = insp_data.get('open_id')
            if not open_id:
                return jsonify({"message": "open_id not found in inspect response"}), 400
        except Exception as e:
            return jsonify({"message": f"Inspect request error: {str(e)}"}), 500
    else:
        open_id = provided_open_id

    # বিভিন্ন প্ল্যাটফর্ম চেষ্টা করো (Google, Facebook, Guest, Huawei ইত্যাদি)
    platforms = [8, 3, 4, 6]   # 8=Google, 3=Facebook, 4=Guest, 6=Huawei
    for pt in platforms:
        token = try_major_login(open_id, access_token, pt)
        if token:
            try:
                decoded_token = jwt.decode(token, options={"verify_signature": False})
                p_id = decoded_token.get("external_type")
                p_name = PLATFORM_MAP.get(p_id, f"Unknown ({p_id})")
                result = {
                    "account_id": decoded_token.get("account_id"),
                    "account_name": decoded_token.get("nickname"),
                    "open_id": open_id,
                    "access_token": access_token,
                    "platform": p_name,
                    "region": decoded_token.get("lock_region"),
                    "status": "success",
                    "token": token
                }
                return jsonify(result), 200
            except Exception:
                continue

    return jsonify({"message": "No valid platform found or account may be banned/invalid"}), 400

@app.route('/token', methods=['GET'])
def oauth_guest():
    uid = request.args.get('uid')
    password = request.args.get('password')
    if not uid or not password:
        return jsonify({"message": "Missing uid or password"}), 400

    oauth_url = "https://100067.connect.garena.com/oauth/guest/token/grant"
    payload = {
        'uid': uid,
        'password': password,
        'response_type': "token",
        'client_type': "2",
        'client_secret': "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
        'client_id': "100067"
    }
    headers = {
        'User-Agent': "GarenaMSDK/4.0.19P9(SM-M526B ;Android 13;pt;BR;)",
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip"
    }

    try:
        oauth_response = requests.post(oauth_url, data=payload, headers=headers, timeout=5)
    except requests.RequestException as e:
        return jsonify({"message": str(e)}), 500

    if oauth_response.status_code != 200:
        try:
            return jsonify(oauth_response.json()), oauth_response.status_code
        except ValueError:
            return jsonify({"message": oauth_response.text}), oauth_response.status_code

    try:
        oauth_data = oauth_response.json()
    except ValueError:
        return jsonify({"message": "Invalid JSON response from OAuth service"}), 500

    if 'access_token' not in oauth_data or 'open_id' not in oauth_data:
        return jsonify({"message": "OAuth response missing access_token or open_id"}), 500

    # /access-jwt-এ ফরোয়ার্ড করার জন্য প্যারামিটার সেট করো
    params = {
        'access_token': oauth_data['access_token'],
        'open_id': oauth_data['open_id']
    }
    with app.test_request_context('/access-jwt', query_string=params):
        return majorlogin_jwt()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=1080, debug=False)