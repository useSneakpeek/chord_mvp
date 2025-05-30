import os
import json
import hmac
import hashlib
import requests
from dotenv import load_dotenv

load_dotenv()


def send_to_webhook(evt_obj, webhook_url, secret, retry_count=3):
    try:
        has_been_sent = False
        error = None
        for i in range(retry_count):
            try:
                signature = create_sha256_signature(evt_obj, secret)
                headers = {
                    "accept": "application/json",
                    "content-type": "application/json",
                    "X-Signature-SHA256": signature
                }
                res = requests.post(webhook_url, json=evt_obj, headers=headers)
                print('response', res.text)
                has_been_sent = True
                error = None
                break
            except Exception as err:
                print(err)

        if has_been_sent == False:
            print({"message": f"ERROR: chord send_to_webhook evt_obj couldn't be sent {error}"})
    except Exception as e:
        print(str(e))


def create_sha256_signature(payload, secret):
    hash_object = hmac.new(secret.encode('utf-8'), msg=json.dumps(payload, separators=(',', ':')).encode('utf-8'), digestmod=hashlib.sha256)
    signature = hash_object.hexdigest()
    return signature


with open('./input.json') as f:
    payload = json.load(f)


webhook_url = os.getenv("WEBHOOK_URL")
secret = os.getenv("WEBHOOK_SECRET")
send_to_webhook(payload, webhook_url, secret)