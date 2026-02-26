from flask import Flask, request, jsonify
import asyncio
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import binascii
import aiohttp
import requests
import json
import like_pb2
import like_count_pb2
import uid_generator_pb2
import threading
import urllib3
import random

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TOKEN_BATCH_SIZE = 50  # BD এর জন্য safe value

app = Flask(__name__)

current_batch_indices = {}
batch_indices_lock = threading.Lock()

def load_tokens(for_visit=False):
    path = "token_bd_visit.json" if for_visit else "token_bd.json"

    try:
        with open(path, "r") as f:
            tokens = json.load(f)
            if isinstance(tokens, list):
                return [t for t in tokens if "token" in t]
    except:
        pass

    return []


def get_next_batch_tokens(all_tokens):
    if not all_tokens:
        return []

    total = len(all_tokens)

    if total <= TOKEN_BATCH_SIZE:
        return all_tokens

    with batch_indices_lock:
        index = current_batch_indices.get("BD", 0)
        start = index
        end = start + TOKEN_BATCH_SIZE

        if end > total:
            batch = all_tokens[start:] + all_tokens[:end-total]
        else:
            batch = all_tokens[start:end]

        current_batch_indices["BD"] = (index + TOKEN_BATCH_SIZE) % total
        return batch
        
def encrypt_message(plaintext):
    key = b'Yg&tc%DEuh6%Zc^8'
    iv = b'6oyZDr22E3ychjM%'
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = pad(plaintext, AES.block_size)
    encrypted = cipher.encrypt(padded)
    return binascii.hexlify(encrypted).decode()


def create_like_proto(uid):
    msg = like_pb2.like()
    msg.uid = int(uid)
    msg.region = "BD"
    return msg.SerializeToString()


def create_profile_proto(uid):
    msg = uid_generator_pb2.uid_generator()
    msg.krishna_ = int(uid)
    msg.teamXdarks = 1
    return msg.SerializeToString()
    
def check_profile(uid, token_dict):
    if not token_dict:
        return None

    enc = encrypt_message(create_profile_proto(uid))

    headers = {
        "User-Agent": "Dalvik/2.1.0",
        "Authorization": f"Bearer {token_dict['token']}",
        "Content-Type": "application/x-www-form-urlencoded",
        "ReleaseVersion": "OB52"
    }

    try:
        r = requests.post(
            "https://clientbp.ggblueshark.com/GetPlayerPersonalShow",
            data=bytes.fromhex(enc),
            headers=headers,
            verify=False,
            timeout=10
        )

        if r.status_code != 200:
            return None

        info = like_count_pb2.Info()
        info.ParseFromString(r.content)
        return info

    except:
        return None


async def send_like(session, payload, token_dict):
    headers = {
        "User-Agent": "Dalvik/2.1.0",
        "Authorization": f"Bearer {token_dict['token']}",
        "Content-Type": "application/x-www-form-urlencoded",
        "ReleaseVersion": "OB52"
    }

    try:
        async with session.post(
            "https://clientbp.ggblueshark.com/LikeProfile",
            data=payload,
            headers=headers,
            timeout=aiohttp.ClientTimeout(total=10)
        ) as r:
            return r.status
    except:
        return 0


async def send_likes(uid, token_batch):
    payload = bytes.fromhex(encrypt_message(create_like_proto(uid)))

    async with aiohttp.ClientSession() as session:
        tasks = [send_like(session, payload, t) for t in token_batch]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    return sum(1 for r in results if r == 200)
    
@app.route("/like", methods=["GET"])
def like_api():
    uid = request.args.get("uid")

    if not uid or not uid.isdigit():
        return jsonify({"status": 0, "error": "Invalid UID"}), 400

    visit_tokens = load_tokens(True)
    if not visit_tokens:
        return jsonify({"status": 0, "error": "Visit tokens missing"}), 500

    like_tokens = load_tokens(False)
    if not like_tokens:
        return jsonify({"status": 0, "error": "Like tokens missing"}), 500

    token_batch = get_next_batch_tokens(like_tokens)

    before_info = check_profile(uid, visit_tokens[0])
    before_likes = 0
    nickname = "Unknown"

    if before_info and hasattr(before_info, "AccountInfo"):
        before_likes = int(before_info.AccountInfo.Likes)
        nickname = before_info.AccountInfo.PlayerNickname or "Unknown"

    try:
        likes_sent = asyncio.run(send_likes(uid, token_batch))
    except:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        likes_sent = loop.run_until_complete(send_likes(uid, token_batch))
        loop.close()

    after_info = check_profile(uid, visit_tokens[0])
    after_likes = before_likes

    if after_info and hasattr(after_info, "AccountInfo"):
        after_likes = int(after_info.AccountInfo.Likes)
        nickname = after_info.AccountInfo.PlayerNickname or nickname

    return jsonify({
        "LikesGivenByAPI": after_likes - before_likes,
        "LikesafterCommand": after_likes,
        "LikesbeforeCommand": before_likes,
        "PlayerNickname": nickname,
        "UID": int(uid),
        "status": 1 if after_likes > before_likes else 2
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=True, use_reloader=False)