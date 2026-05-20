from flask import Flask, request, jsonify
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
from google.protobuf import json_format
from google.protobuf.internal import builder as _builder
import os
import base64
import json
import time
from datetime import datetime
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
SESSION = requests.Session()

_sym_db = _symbol_database.Default()
DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\ndata.proto\"\xbb\x01\n\x04\x44\x61ta\x12\x0f\n\x07\x66ield_2\x18\x02 \x01(\x05\x12\x1e\n\x07\x66ield_5\x18\x05 \x01(\x0b\x32\r.EmptyMessage\x12\x1e\n\x07\x66ield_6\x18\x06 \x01(\x0b\x32\r.EmptyMessage\x12\x0f\n\x07\x66ield_8\x18\x08 \x01(\t\x12\x0f\n\x07\x66ield_9\x18\t \x01(\x05\x12\x1f\n\x08\x66ield_11\x18\x0b \x01(\x0b\x32\r.EmptyMessage\x12\x1f\n\x08\x66ield_12\x18\x0c \x01(\x0b\x32\r.EmptyMessage\"\x0e\n\x0c\x45mptyMessageb\x06proto3')

_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'data_pb2', _globals)

if _descriptor._USE_C_DESCRIPTORS == False:
    DESCRIPTOR._options = None
    _globals['_DATA']._serialized_start = 15
    _globals['_DATA']._serialized_end = 202
    _globals['_EMPTYMESSAGE']._serialized_start = 204
    _globals['_EMPTYMESSAGE']._serialized_end = 218

Data = _sym_db.GetSymbol('Data')
EmptyMessage = _sym_db.GetSymbol('EmptyMessage')

KEY = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
IV = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])

OLD_ACCESS_TOKEN = "3dfa9ab9d25270faf432f7b528564be9ec4790bc744a4eba70225207427d0c40"
OLD_OPEN_ID = "9132c6fb72caccfdc8120d9ec2cc06b8"

FREEFIRE_VERSION = "OB53"
FRIEND_KEY = KEY
FRIEND_IV = IV

TEAM = "D5M"
DEV = "@AlliFF_BOT"

def log_info(message):
    print(f"[INFO] {message}")

def log_error(message):
    print(f"[ERROR] {message}")

def log_debug(message):
    print(f"[DEBUG] {message}")

def add_signature(response_data):
    if isinstance(response_data, dict):
        response_data["TEAM"] = TEAM
        response_data["Dev"] = DEV
    return response_data

def encrypt_api(plain_text):
    plain_text = bytes.fromhex(plain_text)
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
    return cipher_text.hex()

def encrypt_friend_payload(hex_data):
    raw = bytes.fromhex(hex_data)
    cipher = AES.new(FRIEND_KEY, AES.MODE_CBC, FRIEND_IV)
    return cipher.encrypt(pad(raw, AES.block_size))

def encode_id(number):
    number = int(number)
    encoded_bytes = []
    while True:
        byte = number & 0x7F
        number >>= 7
        if number:
            byte |= 0x80
        encoded_bytes.append(byte)
        if not number:
            break
    return bytes(encoded_bytes).hex()

def decode_jwt(token):
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return None
        
        payload = parts[1]
        
        padding = 4 - len(payload) % 4
        if padding != 4:
            payload += '=' * padding
        
        decoded_bytes = base64.urlsafe_b64decode(payload)
        decoded_data = json.loads(decoded_bytes)
        
        return decoded_data
    except Exception as e:
        log_error(f"Error decoding JWT: {e}")
        return None

def get_server_from_region(region):
    server_mapping = {
        "EUROPE": "Europe Server",
        "ASIA": "Asia Server",
        "MIDDLE_EAST": "Middle East Server",
        "NORTH_AMERICA": "North America Server",
        "SOUTH_AMERICA": "South America Server",
    }
    return server_mapping.get(region, f"Unknown Server ({region})")

def get_access_token_from_credentials(uid, password):
    try:
        headers = {
            "Host": "100067.connect.garena.com",
            "User-Agent": "GarenaMSDK/4.0.19P4(G011A ;Android 9;en;US;)",
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "close"
        }
        
        data = {
            "uid": str(uid),
            "password": str(password),
            "response_type": "token",
            "client_type": "2",
            "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
            "client_id": "100067"
        }
        
        response = requests.post("https://100067.connect.garena.com/oauth/guest/token/grant",
                                headers=headers, data=data, verify=False, timeout=30)
        
        if response.status_code != 200:
            return None, f"Server error: {response.status_code}"
        
        data_response = response.json()
        
        if data_response.get("success") is True:
            resp = data_response.get("response", {})
            if resp.get("error") == "auth_error":
                return None, "Invalid credentials"
        
        access_token = data_response.get("access_token")
        open_id = data_response.get("open_id")
        
        if access_token and open_id:
            return {"access_token": access_token, "open_id": open_id, "uid": uid}, None
        else:
            return None, "Failed to receive tokens"
            
    except Exception as e:
        log_error(f"Error in get_access_token_from_credentials: {str(e)}")
        return None, f"Internal error: {str(e)}"

def get_jwt_from_access_token(access_token, open_id, uid):
    try:
        data = bytes.fromhex('1a13323032362d30312d31342031323a31393a3032220966726565206669726528013a07312e3132302e324232416e64726f6964204f532039202f204150492d3238202850492f72656c2e636a772e32303232303531382e313134313333294a0848616e6468656c64520c4d544e2f537061636574656c5a045749464960800a68d00572033234307a2d7838362d3634205353453320535345342e3120535345342e32204156582041565832207c2032343030207c20348001e61e8a010f416472656e6f2028544d292036343092010d4f70656e474c20455320332e329a012b476f6f676c657c36323566373136662d393161372d343935622d396631362d303866653964336336353333a2010d3137362e32382e3134352e3239aa01026172b201203931333263366662373263616363666463383132306439656332636330366238ba010134c2010848616e6468656c64ca010d4f6e65506c7573204135303130d201025347ea014033646661396162396432353237306661663433326637623532383536346265396563343739306263373434613465626137303232353230373432376430633430f00101ca020c4d544e2f537061636574656cd2020457494649ca03203161633462383065636630343738613434323033626638666163363132306635e003b5ee02e803c28302f003af13f80384078004cf92028804b5ee029004cf92029804b5ee02b00404c80403d2043d2f646174612f6170702f636f6d2e6474732e667265656669726574682d49316855713474347641365f516f34432d58676165513d3d2f6c69622f61726de00401ea045f65363261623933353464386662356662303831646233333861636233333439317c2f646174612f6170702f636f6d2e6474732e667265656669726574682d49316855713474347641365f516f34432d58676165513d3d2f626173652e61706bf00406f804018a050233329a050a32303139313139363234b205094f70656e474c455332b805ff01c00504e005edb402ea05093372645f7061727479f2055c4b7173485438512b6c73302b4464496c2f4f617652726f7670795a596377676e51485151636d57776a476d587642514b4f4d63747870796f7054515754487653354a714d6967476b534c434c423651387839544161764d666c6a6f3d8806019006019a060134a2060134b206224006474f56540a011a5d0e115e00170d4b6e085709510a685a02586800096f000161')
        
        data = data.replace(OLD_OPEN_ID.encode(), open_id.encode())
        data = data.replace(OLD_ACCESS_TOKEN.encode(), access_token.encode())
        
        d = encrypt_api(data.hex())
        Final_Payload = bytes.fromhex(d)
        
        headers = {
            "Host": "loginbp.ggpolarbear.com",
            "X-Unity-Version": "2018.4.11f1",
            "Accept": "*/*",
            "Authorization": "Bearer",
            "ReleaseVersion": "OB53",
            "X-GA": "v1 1",
            "Accept-Encoding": "gzip, deflate, br",
            "Accept-Language": "en-GB,en-US;q=0.9,en;q=0.8",
            "Content-Type": "application/x-www-form-urlencoded",
            "Content-Length": str(len(Final_Payload)),
            "User-Agent": "Free%20Fire/2019118692 CFNetwork/3826.500.111.2.2 Darwin/24.4.0",
            "Connection": "keep-alive"
        }
        
        URL = "https://loginbp.ggpolarbear.com/MajorLogin"
        RESPONSE = requests.post(URL, headers=headers, data=Final_Payload, verify=False, timeout=30)
        
        if RESPONSE.status_code == 200:
            if len(RESPONSE.text) < 10:
                return None
            BASE64_TOKEN = RESPONSE.text[RESPONSE.text.find("eyJhbGciOiJIUzI1NiIsInN2ciI6IjEiLCJ0eXAiOiJKV1QifQ"):-1]
            second_dot_index = BASE64_TOKEN.find(".", BASE64_TOKEN.find(".") + 1)
            BASE64_TOKEN = BASE64_TOKEN[:second_dot_index + 44]
            return BASE64_TOKEN
        else:
            log_error(f"MajorLogin failed with status: {RESPONSE.status_code}")
            return None
            
    except Exception as e:
        log_error(f"Error in get_jwt_from_access_token: {str(e)}")
        return None

def get_jwt_direct(uid, password):
    try:
        token_data, error = get_access_token_from_credentials(uid, password)
        if error:
            return None, error
        
        jwt_token = get_jwt_from_access_token(
            token_data["access_token"], 
            token_data["open_id"], 
            token_data["uid"]
        )
        
        if jwt_token:
            return jwt_token, None
        else:
            return None, "Failed to convert access token to JWT"
            
    except Exception as e:
        log_error(f"Error in get_jwt_direct: {str(e)}")
        return None, f"Internal error: {str(e)}"

def get_jwt_from_access_token_only(access_token):
    try:
        headers = {
            "Host": "100067.connect.garena.com",
            "User-Agent": "GarenaMSDK/4.0.19P4(G011A ;Android 9;en;US;)",
            "Accept-Encoding": "gzip, deflate, br"
        }
        
        inspect_url = f"https://100067.connect.garena.com/oauth/token/inspect?token={access_token}"
        response = requests.get(inspect_url, headers=headers, verify=False, timeout=30)
        
        if response.status_code == 200:
            inspect_data = response.json()
            open_id = inspect_data.get("open_id")
            uid = inspect_data.get("uid")
            
            if open_id and uid:
                jwt_token = get_jwt_from_access_token(access_token, open_id, str(uid))
                if jwt_token:
                    return jwt_token, None
                else:
                    return None, "Failed to convert access token to JWT"
            else:
                return None, "Could not extract open_id and uid from access token"
        else:
            return None, f"Invalid access token: {response.status_code}"
            
    except Exception as e:
        log_error(f"Error in get_jwt_from_access_token_only: {str(e)}")
        return None, f"Internal error: {str(e)}"

def update_bio_with_jwt(jwt_token, new_bio):
    try:
        data = Data()
        data.field_2 = 17
        data.field_5.CopyFrom(EmptyMessage())
        data.field_6.CopyFrom(EmptyMessage())
        data.field_8 = new_bio
        data.field_9 = 1
        data.field_11.CopyFrom(EmptyMessage())
        data.field_12.CopyFrom(EmptyMessage())

        data_bytes = data.SerializeToString()
        padded_data = pad(data_bytes, AES.block_size)
        cipher = AES.new(KEY, AES.MODE_CBC, IV)
        encrypted_data = cipher.encrypt(padded_data)
        formatted_encrypted_data = ' '.join([f"{byte:02X}" for byte in encrypted_data])

        game_api_url = "https://clientbp.ggpolarbear.com/UpdateSocialBasicInfo"
        data_bytes = bytes.fromhex(formatted_encrypted_data.replace(" ", ""))
        headers = {
            "Expect": "100-continue",
            "Authorization": f"Bearer {jwt_token}",
            "X-Unity-Version": "2018.4.11f1",
            "X-GA": "v1 1",
            "ReleaseVersion": FREEFIRE_VERSION,
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 11; SM-A305F Build/RP1A.200720.012)",
            "Host": "clientbp.ggwhitehawk.com",
            "Connection": "Keep-Alive",
            "Accept-Encoding": "gzip"
        }
        
        game_response = requests.post(game_api_url, headers=headers, data=data_bytes, timeout=10)
        
        if game_response.status_code == 200:
            return True, "Bio updated successfully"
        else:
            return False, f"Failed to update bio: {game_response.status_code}"
    except Exception as e:
        return False, f"Error updating bio: {str(e)}"

def TOKEN_MAKER(OLD_ACCESS_TOKEN, NEW_ACCESS_TOKEN, OLD_OPEN_ID, NEW_OPEN_ID, uid):
    now = datetime.now()
    now = str(now)[:len(str(now)) - 7]
    data = bytes.fromhex('1a13323032362d30312d31342031323a31393a3032220966726565206669726528013a07312e3132302e324232416e64726f6964204f532039202f204150492d3238202850492f72656c2e636a772e32303232303531382e313134313333294a0848616e6468656c64520c4d544e2f537061636574656c5a045749464960800a68d00572033234307a2d7838362d3634205353453320535345342e3120535345342e32204156582041565832207c2032343030207c20348001e61e8a010f416472656e6f2028544d292036343092010d4f70656e474c20455320332e329a012b476f6f676c657c36323566373136662d393161372d343935622d396631362d303866653964336336353333a2010d3137362e32382e3134352e3239aa01026172b201203931333263366662373263616363666463383132306439656332636330366238ba010134c2010848616e6468656c64ca010d4f6e65506c7573204135303130d201025347ea014033646661396162396432353237306661663433326637623532383536346265396563343739306263373434613465626137303232353230373432376430633430f00101ca020c4d544e2f537061636574656cd2020457494649ca03203161633462383065636630343738613434323033626638666163363132306635e003b5ee02e803c28302f003af13f80384078004cf92028804b5ee029004cf92029804b5ee02b00404c80403d2043d2f646174612f6170702f636f6d2e6474732e667265656669726574682d49316855713474347641365f516f34432d58676165513d3d2f6c69622f61726de00401ea045f65363261623933353464386662356662303831646233333861636233333439317c2f646174612f6170702f636f6d2e6474732e667265656669726574682d49316855713474347641365f516f34432d58676165513d3d2f626173652e61706bf00406f804018a050233329a050a32303139313139363234b205094f70656e474c455332b805ff01c00504e005edb402ea05093372645f7061727479f2055c4b7173485438512b6c73302b4464496c2f4f617652726f7670795a596377676e51485151636d57776a476d587642514b4f4d63747870796f7054515754487653354a714d6967476b534c434c423651387839544161764d666c6a6f3d8806019006019a060134a2060134b206224006474f56540a011a5d0e115e00170d4b6e085709510a685a02586800096f000161')
    data = data.replace(OLD_OPEN_ID.encode(), NEW_OPEN_ID.encode())
    data = data.replace(OLD_ACCESS_TOKEN.encode(), NEW_ACCESS_TOKEN.encode())
    d = encrypt_api(data.hex())
    Final_Payload = bytes.fromhex(d)
    
    headers = {
        "Host": "loginbp.ggpolarbear.com",   # Fixed: no trailing slash
        "X-Unity-Version": "2018.4.11f1",
        "Accept": "*/*",
        "Authorization": "Bearer",
        "ReleaseVersion": "OB53",
        "X-GA": "v1 1",
        "Accept-Encoding": "gzip, deflate, br",
        "Accept-Language": "en-GB,en-US;q=0.9,en;q=0.8",
        "Content-Type": "application/x-www-form-urlencoded",
        "Content-Length": str(len(Final_Payload)),
        "User-Agent": "Free%20Fire/2019118692 CFNetwork/3826.500.111.2.2 Darwin/24.4.0",
        "Connection": "keep-alive"
    }
    
    URL = "https://loginbp.ggpolarbear.com/MajorLogin"
    RESPONSE = requests.post(URL, headers=headers, data=Final_Payload, verify=False)
    
    if RESPONSE.status_code == 200:
        if len(RESPONSE.text) < 10:
            return False
        # Fixed: correct JWT header string
        BASE64_TOKEN = RESPONSE.text[RESPONSE.text.find("eyJhbGciOiJIUzI1NiIsInN2ciI6IjEiLCJ0eXAiOiJKV1QifQ"):-1]
        second_dot_index = BASE64_TOKEN.find(".", BASE64_TOKEN.find(".") + 1)
        BASE64_TOKEN = BASE64_TOKEN[:second_dot_index + 44]
        return BASE64_TOKEN
    else:
        print(f"MajorLogin failed with status: {RESPONSE.status_code}")
        print(f"Response: {RESPONSE.text}")
        return False

@app.route('/')
def home():
    response_data = {
        "status": "active",
        "features": {
            "bio_update": "Change bio",
            "friend_list": "Friend list",
            "add_friend": "Add friend",
            "remove_friend": "Remove friend",
            "get_token": "Get token"
        },
        "endpoints": {
            "bio": "/bio?access=TOKEN&new_bio=TEXT",
            "bio_credentials": "/bio?uid=ID&password=PASS&new_bio=TEXT",
            "friends": "/friends/JWT_TOKEN",
            "add_friend": "/add/UID/PASSWORD/FRIEND_ID",
            "remove_friend": "/remove/UID/PASSWORD/FRIEND_ID",
            "get_token": "/get?uid=ID&password=PASS",
            "decode_token": "/decode_token?token=JWT_TOKEN"
        }
    }
    return jsonify(add_signature(response_data))

@app.route('/bio', methods=['GET'])
def handle_bio_request():
    try:
        access = request.args.get('access')
        uid = request.args.get('uid')
        password = request.args.get('password')
        new_bio = request.args.get('new_bio')

        jwt_token = None
        error_message = None
        
        if access:
            log_debug(f"Using access token: {access[:20]}...")
            jwt_token, error_message = get_jwt_from_access_token_only(access)
            
        elif uid and password:
            log_debug(f"Using uid: {uid}, password: {password[:5]}...")
            jwt_token, error_message = get_jwt_direct(uid, password)
            
        else:
            return jsonify(add_signature({
                "error": "You must provide either access token (access=) or uid and password"
            })), 400

        if not jwt_token:
            return jsonify(add_signature({"error": error_message})), 400

        if not new_bio:
            return jsonify(add_signature({
                "message": "Token obtained successfully",
                "token": jwt_token
            }))

        success, message = update_bio_with_jwt(jwt_token, new_bio)
        
        if success:
            return jsonify(add_signature({
                "message": message,
                "bio": new_bio
            }))
        else:
            return jsonify(add_signature({
                "error": message
            })), 400

    except Exception as e:
        log_error(f"Error in handle_bio_request: {str(e)}")
        return jsonify(add_signature({
            "error": f"An error occurred: {str(e)}"
        })), 500

@app.route('/get_jwt', methods=['GET'])
def get_token_only():
    try:
        access = request.args.get('access')
        uid = request.args.get('uid')
        password = request.args.get('password')
        
        jwt_token = None
        error_message = None
        
        if access:
            jwt_token, error_message = get_jwt_from_access_token_only(access)
        elif uid and password:
            jwt_token, error_message = get_jwt_direct(uid, password)
        else:
            return jsonify(add_signature({
                "error": "You must provide either access or uid and password"
            })), 400
        
        if not jwt_token:
            return jsonify(add_signature({
                "error": error_message
            })), 400
        
        return jsonify(add_signature({
            "message": "Token obtained successfully",
            "token": jwt_token
        }))
        
    except Exception as e:
        log_error(f"Error in get_token_only: {str(e)}")
        return jsonify(add_signature({
            "error": f"An error occurred: {str(e)}"
        })), 500

@app.route('/friends/<path:jwt>', methods=['GET'])
def friend_list(jwt):
    if not jwt or jwt.count(".") != 2:
        return jsonify(add_signature({
            "status": "error",
            "message": "Invalid JWT"
        })), 400

    headers = {
        "Expect": "100-continue",
        "Authorization": f"Bearer {jwt}",
        "X-Unity-Version": "2018.4.11f1",
        "X-GA": "v1 1",
        "ReleaseVersion": FREEFIRE_VERSION,
        "Content-Type": "application/octet-stream",
        "User-Agent": "Dalvik/2.1.0 (Linux; Android 11)",
        "Connection": "Keep-Alive",
        "Accept-Encoding": "gzip"
    }

    payload_hex = "080110011001"
    encrypted_payload = encrypt_friend_payload(payload_hex)

    try:
        r = requests.post(
            "https://clientbp.ggpolarbear.com/GetFriend",
            headers=headers,
            data=encrypted_payload,
            timeout=15,
            verify=False
        )

        if r.status_code != 200:
            return jsonify(add_signature({
                "status": "error",
                "message": "Free Fire server error",
                "code": r.status_code
            })), 502

        from collections import OrderedDict
        
        class Friends:
            def __init__(self):
                self.field1 = []
            
            def ParseFromString(self, data):
                import struct
                pos = 0
                while pos < len(data):
                    field_number = (data[pos] >> 3) & 0x07
                    wire_type = data[pos] & 0x07
                    pos += 1
                    
                    if wire_type == 2:
                        length = data[pos]
                        pos += 1
                        value = data[pos:pos+length]
                        pos += length
                        
                        if field_number == 1:
                            friend_obj = OrderedDict()
                            sub_pos = 0
                            while sub_pos < len(value):
                                sub_field_num = (value[sub_pos] >> 3) & 0x07
                                sub_wire_type = value[sub_pos] & 0x07
                                sub_pos += 1
                                
                                if sub_wire_type == 0:
                                    varint = 0
                                    shift = 0
                                    while True:
                                        byte = value[sub_pos]
                                        sub_pos += 1
                                        varint |= (byte & 0x7F) << shift
                                        if not (byte & 0x80):
                                            break
                                        shift += 7
                                    
                                    if sub_field_num == 1:
                                        friend_obj["ID"] = str(varint)
                                
                                elif sub_wire_type == 2:
                                    length = value[sub_pos]
                                    sub_pos += 1
                                    string_value = value[sub_pos:sub_pos+length].decode('utf-8', errors='ignore')
                                    sub_pos += length
                                    
                                    friend_obj[f"field_{sub_field_num}"] = string_value
                            
                            self.field1.append(friend_obj)
        
        pb = Friends()
        pb.ParseFromString(r.content)

        raw_list = []
        for entry in pb.field1:
            uid = str(entry.get("ID", "unknown"))
            name = "unknown"

            for k, v in entry.items():
                if isinstance(v, str) and k != "ID":
                    name = v
                    break

            raw_list.append({
                "uid": uid,
                "name": name
            })

        if not raw_list:
            return jsonify(add_signature({
                "friends_count": 0,
                "friends_list": [],
                "my_info": None,
                "status": "success",
                "timestamp": int(time.time())
            }))

        my_info = raw_list[-1] 
        friends_list = raw_list[:-1] 

        return jsonify(add_signature({
            "friends_count": len(friends_list),
            "friends_list": friends_list,
            "my_info": my_info,
            "status": "success",
            "timestamp": int(time.time())
        }))

    except Exception as e:
        return jsonify(add_signature({
            "status": "error",
            "message": "Friend list failed",
            "details": str(e)
        })), 500

@app.route('/add/<uid>/<password>/<friend_id>', methods=['GET'])
def add_friend(uid, password, friend_id):
    jwt_token, error = get_jwt_direct(uid, password)
    if not jwt_token:
        response_data = {
            "error": "Failed to obtain JWT",
            "status": "error"
        }
        return jsonify(add_signature(response_data)), 401
    
    enc_id = encode_id(friend_id)
    payload = f"08a7c4839f1e10{enc_id}1801"
    enc_data = encrypt_api(payload)
    
    try:
        response = requests.post(
            "https://clientbp.ggpolarbear.com/RequestAddingFriend",
            headers={
                "Authorization": f"Bearer {jwt_token}",
                "X-Unity-Version": "2018.4.11f1",
                "X-GA": "v1 1",
                "ReleaseVersion": FREEFIRE_VERSION,
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": "Dalvik/2.1.0 (Linux; Android 9)",
                "Connection": "Keep-Alive",
                "Accept-Encoding": "gzip"
            },
            data=bytes.fromhex(enc_data),
            timeout=10
        )
        
        if response.status_code == 200:
            response_data = {
                "status": "success",
                "message": "Friend request sent successfully",
                "details": {
                    "friend_id": friend_id,
                    "response_code": response.status_code,
                    "server_response": response.text
                }
            }
            return jsonify(add_signature(response_data))
        else:
            response_data = {
                "status": "error",
                "message": "Failed to send friend request",
                "details": {
                    "response_code": response.status_code,
                    "server_response": response.text
                }
            }
            return jsonify(add_signature(response_data))
            
    except Exception as e:
        response_data = {
            "status": "error",
            "message": "An error occurred while sending friend request",
            "error_details": str(e)
        }
        return jsonify(add_signature(response_data)), 500

@app.route('/remove/<uid>/<password>/<friend_id>', methods=['GET'])
def remove_friend(uid, password, friend_id):
    jwt_token, error = get_jwt_direct(uid, password)
    if not jwt_token:
        response_data = {
            "error": "Failed to obtain JWT",
            "status": "error"
        }
        return jsonify(add_signature(response_data)), 401
    
    enc_id = encode_id(friend_id)
    payload = f"08a7c4839f1e10{enc_id}1802"
    enc_data = encrypt_api(payload)
    
    try:
        response = requests.post(
            "https://clientbp.ggpolarbear.com/RemoveFriend",
            headers={
                "Authorization": f"Bearer {jwt_token}",
                "X-Unity-Version": "2018.4.11f1",
                "X-GA": "v1 1",
                "ReleaseVersion": FREEFIRE_VERSION,
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": "Dalvik/2.1.0 (Linux; Android 9)",
                "Connection": "Keep-Alive",
                "Accept-Encoding": "gzip"
            },
            data=bytes.fromhex(enc_data),
            timeout=10
        )
        
        if response.status_code == 200:
            response_data = {
                "status": "success",
                "message": "Friend removed successfully",
                "details": {
                    "friend_id": friend_id,
                    "response_code": response.status_code,
                    "server_response": response.text
                }
            }
            return jsonify(add_signature(response_data))
        else:
            response_data = {
                "status": "error",
                "message": "Failed to remove friend",
                "details": {
                    "response_code": response.status_code,
                    "server_response": response.text
                }
            }
            return jsonify(add_signature(response_data))
            
    except Exception as e:
        response_data = {
            "status": "error",
            "message": "An error occurred while removing friend",
            "error_details": str(e)
        }
        return jsonify(add_signature(response_data)), 500

@app.route('/get', methods=['GET'])
def check_token():
    try:
        uid = request.args.get('uid')
        password = request.args.get('password')
        
        if not uid or not password:
            return jsonify(add_signature({
                "status": "error",
                "message": "Missing uid or password parameter"
            }))
        
        url = "https://100067.connect.garena.com/oauth/guest/token/grant"
        headers = {
            "Host": "100067.connect.garena.com",
            "User-Agent": "GarenaMSDK/4.0.19P4(G011A ;Android 9;en;US;)",
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "close",
        }
        data = {
            "uid": f"{uid}",
            "password": f"{password}",
            "response_type": "token",
            "client_type": "2",
            "client_secret": "",
            "client_id": "100067",
        }
        
        response = requests.post(url, headers=headers, data=data)
        
        try:
            garena_data = response.json()
        except Exception as e:
            return jsonify(add_signature({
                "status": "error", 
                "message": "Invalid response from Garena"
            }))

        if "access_token" not in garena_data or "open_id" not in garena_data:
            return jsonify(add_signature({
                "status": "error", 
                "message": f"Missing keys in response"
            }))

        NEW_ACCESS_TOKEN = garena_data['access_token']
        NEW_OPEN_ID = garena_data['open_id']
        
        access_token_garena = garena_data.get('access_token', 'N/A')
        
        OLD_ACCESS_TOKEN = "3dfa9ab9d25270faf432f7b528564be9ec4790bc744a4eba70225207427d0c40"
        OLD_OPEN_ID = "9132c6fb72caccfdc8120d9ec2cc06b8"
        
        token = TOKEN_MAKER(OLD_ACCESS_TOKEN, NEW_ACCESS_TOKEN, OLD_OPEN_ID, NEW_OPEN_ID, uid)
        
        if token:
            token_data = decode_jwt(token)
            
            if token_data:
                account_id = token_data.get('account_id', 'N/A')
                nickname = token_data.get('nickname', 'N/A')
                noti_region = token_data.get('noti_region', 'N/A')
                lock_region = token_data.get('lock_region', 'N/A')
                external_id = token_data.get('external_id', 'N/A')
                country_code = token_data.get('country_code', 'N/A')
                external_uid = token_data.get('external_uid', 'N/A')
                
                exp_timestamp = token_data.get('exp', 'N/A')
                exp_date = 'N/A'
                if exp_timestamp != 'N/A':
                    try:
                        exp_date = datetime.fromtimestamp(exp_timestamp).strftime('%Y-%m-%d %H:%M:%S')
                    except:
                        exp_date = str(exp_timestamp)
                
                server = get_server_from_region(lock_region or noti_region)
                
                return jsonify(add_signature({
                    "status": "success",
                    "token": token,
                    "access_token": access_token_garena,
                    "account_info": {
                        "account_id": account_id,
                        "uid": uid,
                        "password": password,
                        "external_uid": external_uid,
                        "nickname": nickname,
                        "server": server,
                        "region": lock_region or noti_region,
                        "country_code": country_code,
                        "external_id": external_id,
                        "token_expiry": exp_date
                    },
                    "garena_tokens": {
                        "access_token": access_token_garena,
                        "open_id": garena_data.get('open_id', 'N/A'),
                        "refresh_token": garena_data.get('refresh_token', 'N/A'),
                        "expires_in": garena_data.get('expires_in', 'N/A'),
                        "scope": garena_data.get('scope', 'N/A')
                    },
                    "decoded_token": token_data,
                    "response_data": garena_data,
                }))
            else:
                return jsonify(add_signature({
                    "status": "success",
                    "token": token,
                    "access_token": access_token_garena,
                    "account_info": {
                        "uid": uid,
                        "password": password,
                        "message": "Token generated successfully but could not decode for additional info"
                    },
                    "garena_tokens": {
                        "access_token": access_token_garena,
                        "open_id": garena_data.get('open_id', 'N/A')
                    },
                }))
        else:
            return jsonify(add_signature({
                "status": "failure", 
                "message": "Failed to generate token"
            }))
    except Exception as e:
        return jsonify(add_signature({
            "status": "error", 
            "message": str(e)
        }))

@app.route('/decode_token', methods=['GET'])
def decode_token_endpoint():
    try:
        token = request.args.get('token')
        if not token:
            return jsonify(add_signature({
                "status": "error",
                "message": "Token parameter is required"
            }))
        
        token_data = decode_jwt(token)
        
        if token_data:
            account_id = token_data.get('account_id', 'N/A')
            nickname = token_data.get('nickname', 'N/A')
            noti_region = token_data.get('noti_region', 'N/A')
            lock_region = token_data.get('lock_region', 'N/A')
            external_id = token_data.get('external_id', 'N/A')
            country_code = token_data.get('country_code', 'N/A')
            external_uid = token_data.get('external_uid', 'N/A')
            exp_timestamp = token_data.get('exp', 'N/A')
            
            exp_date = 'N/A'
            if exp_timestamp != 'N/A':
                try:
                    exp_date = datetime.fromtimestamp(exp_timestamp).strftime('%Y-%m-%d %H:%M:%S')
                except:
                    exp_date = str(exp_timestamp)
            
            server = get_server_from_region(lock_region or noti_region)
            
            return jsonify(add_signature({
                "status": "success",
                "decoded_token": token_data,
                "account_info": {
                    "account_id": account_id,
                    "nickname": nickname,
                    "server": server,
                    "region": lock_region or noti_region,
                    "country_code": country_code,
                    "external_id": external_id,
                    "external_uid": external_uid,
                    "token_expiry": exp_date
                },
            }))
        else:
            return jsonify(add_signature({
                "status": "error",
                "message": "Failed to decode token"
            }))
    except Exception as e:
        return jsonify(add_signature({
            "status": "error", 
            "message": str(e)
        }))

@app.errorhandler(404)
def not_found(error):
    return jsonify(add_signature({
        "error": "Not Found",
        "message": "Page not found"
    })), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify(add_signature({
        "error": "Internal Server Error",
        "message": "An internal server error occurred"
    })), 500

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 3000))
    log_info(f"Running service on port {port}")
    app.run(host='0.0.0.0', port=port, debug=True)