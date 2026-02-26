from flask import Flask, request, jsonify
import asyncio, json, binascii, aiohttp, requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from google.protobuf.json_format import MessageToJson
from google.protobuf.message import DecodeError

import like_pb2
import like_count_pb2
import uid_generator_pb2

app = Flask(__name__)

# ===================== CONFIG =====================
AES_KEY = b'Yg&tc%DEuh6%Zc^8'
AES_IV  = b'6oyZDr22E3ychjM%'
BD_PROFILE_URL = "https://clientbp.ggblueshark.com/GetPlayerPersonalShow"
BD_LIKE_URL    = "https://clientbp.ggblueshark.com/LikeProfile"

# ===================== TOKEN LOADER =====================
def load_tokens():
    try:
        with open("token_bd.json", "r") as f:
            data = json.load(f)

        # Ensure it's a list
        if isinstance(data, list) and len(data) > 0:
            # Ensure first item has token key
            if "token" in data[0]:
                return data
            else:
                print("❌ 'token' key missing in JSON objects")
                return None
        else:
            print("❌ JSON is not a valid token list")
            return None

    except Exception as e:
        print("❌ Token load error:", e)
        return None

# ===================== ENCRYPT =====================
def encrypt_message(data: bytes):
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    return binascii.hexlify(cipher.encrypt(pad(data, AES.block_size))).decode()

# ===================== UID PROTO =====================
def create_uid_proto(uid):
    try:
        msg = uid_generator_pb2.uid_generator()
        msg.saturn_ = int(uid)
        msg.garena = 1
        return msg.SerializeToString()
    except:
        return None

def enc_uid(uid):
    proto = create_uid_proto(uid)
    if not proto:
        return None
    return encrypt_message(proto)

# ===================== PROFILE REQUEST =====================
def get_profile(enc_uid_hex, token):
    try:
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "Dalvik/2.1.0",
            "ReleaseVersion": "OB52"
        }

        r = requests.post(
            BD_PROFILE_URL,
            data=bytes.fromhex(enc_uid_hex),
            headers=headers,
            verify=False,
            timeout=10
        )

        print("Status Code:", r.status_code)
        print("Raw Response Length:", len(r.content))

        if r.status_code != 200 or not r.content:
            print("Profile request failed")
            return None

        info = like_count_pb2.Info()
        info.ParseFromString(r.content)

        print("Parsed Successfully")
        return info

    except Exception as e:
        print("PROFILE ERROR:", e)
        return None

# ===================== LIKE PROTO =====================
def create_like_proto(uid):
    try:
        msg = like_pb2.like()
        msg.uid = int(uid)
        msg.region = "BD"
        return msg.SerializeToString()
    except:
        return None

# ===================== SEND LIKE =====================
async def send_like(enc_like_hex, token):
    
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "Dalvik/2.1.0",
        "ReleaseVersion": "OB52"
    }
    async with aiohttp.ClientSession() as s:
        async with s.post(
            BD_LIKE_URL,
            data=bytes.fromhex(enc_like_hex),
            headers=headers
        ) as r:
            return r.status == 200

# ===================== API =====================
@app.route("/like", methods=["GET"])
def like_api():

    uid = request.args.get("uid")

    if not uid or not uid.isdigit():
        return jsonify({"status": 0, "error": "Invalid UID"}), 400

    tokens = load_tokens()

    if not tokens:
        return jsonify({"error": "Token file problem"}), 500

    token = tokens[0].get("token")

    if not token:
        return jsonify({"error": "Invalid token format"}), 500

    enc = enc_uid(uid)

    if not enc:
        return jsonify({"status": 0, "error": "UID encryption failed"}), 500

    # ---------- BEFORE ----------
    before_proto = get_profile(enc, token)
    if before_proto:
        try:
            before_json = json.loads(MessageToJson(before_proto))
            before_like = int(before_json.get("AccountInfo", {}).get("Likes", 0))
        except:
            before_like = 0
    else:
        before_like = 0

    # ---------- SEND LIKES ----------
    like_proto = create_like_proto(uid)
    if not like_proto:
        return jsonify({"status": 0, "error": "Like proto failed"}), 500

    enc_like = encrypt_message(like_proto)

    async def run_likes():
        tasks = []
        for i in range(100):
            t = tokens[i % len(tokens)]["token"]
            tasks.append(send_like(enc_like, t))
        await asyncio.gather(*tasks)

    asyncio.run(run_likes())

    # ---------- AFTER ----------
    after_proto = get_profile(enc, token)
    if after_proto:
        try:
            after_json = json.loads(MessageToJson(after_proto))
            after_like = int(after_json.get("AccountInfo", {}).get("Likes", before_like))
            name = after_json.get("AccountInfo", {}).get("PlayerNickname", "")
        except:
            after_like = before_like
            name = ""
    else:
        after_like = before_like
        name = ""

    return jsonify({
        "status": 1,
        "region": "BD",
        "UID": int(uid),
        "PlayerNickname": name,
        "LikesbeforeCommand": before_like,
        "LikesafterCommand": after_like,
        "LikesGivenByAPI": after_like - before_like
    })

# ===================== RUN =====================
if __name__ == "__main__":
    print("🔥 BD ONLY LIKE API RUNNING")
    app.run(host="0.0.0.0", port=5000, debug=True)
