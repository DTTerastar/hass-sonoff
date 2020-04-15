# -*- coding: utf-8 -*-
import argparse
import base64
import hashlib
import hmac
import json
import random
import re
import string

import requests
import sys
import time
import uuid

# named params	
if not sys.argv[1].startswith('-') and not sys.argv[2].startswith('-'):
    username = sys.argv[1]
    password = sys.argv[2]

else:
    parser = argparse.ArgumentParser()
    parser.add_argument('-u', '--username', help='email/phone number used to login in eWeLink app')
    parser.add_argument('-p', '--password', help='password for email/account')

    args = parser.parse_args()

    # positional params
    if hasattr(args, 'username') and hasattr(args, 'password'):
        username = args.username
        password = args.password

    else:
        print('Please read the instructions better!')
        sys.exit(1)


def gen_nonce(length=8):
    """Generate pseudorandom number."""
    return ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(8))


headers = {'Content-Type': 'application/json;charset=UTF-8'}
user_details = {}
api_region = 'us'
imei = str(uuid.uuid4())
model = 'iPhone10,6'
romVersion = '11.1.2'


def do_login():
    global api_region

    app_details = {
        'password': password,
        'version': '6',
        'ts': int(time.time()),
        'nonce': gen_nonce(15),
        'appid': 'oeVkj2lYFGnJu5XUtWisfW4utiN4u9Mq',
        'imei': imei,
        'os': 'iOS',
        'model': model,
        'romVersion': romVersion,
        'appVersion': random.choice(
            ['3.5.3', '3.5.4', '3.5.6', '3.5.8', '3.5.10', '3.5.12', '3.6.0', '3.6.1', '3.7.0', '3.8.0', '3.9.0',
             '3.9.1', '3.10.0', '3.11.0'])
    }

    if '@' not in username:
        app_details['phoneNumber'] = username
    else:
        app_details['email'] = username

    # python3.6+
    decryptedAppSecret = b'6Nz4n0xA8s8qdxQf2GqurZj2Fs55FUvM'
    hex_dig = hmac.new(decryptedAppSecret, str.encode(json.dumps(app_details)), digestmod=hashlib.sha256).digest()

    sign = base64.b64encode(hex_dig).decode()

    headers.update({'Authorization': 'Sign ' + sign})
    r = requests.post('https://%s-api.coolkit.cc:8080/api/user/login' % api_region, headers=headers, json=app_details)
    resp = r.json()

    if 'error' in resp and 'region' in resp and resp['error'] == 301:

        print(
            "found new region: >>> %s <<< (you should change api_region option to this value in configuration.yaml)" % api_region)
        # re-login using the new localized endpoint
        api_region = resp['region']
        do_login()

    else:
        if 'at' not in resp:
            print('Login failed! Please check credentials!')

        global user_details
        user_details = r.json()
        return user_details


def get_devices():
    headers.update({'Authorization': 'Bearer ' + user_details['at']})
    url = 'https://{}-api.coolkit.cc:8080/api/user/device?lang=en&apiKey={}&getTags=1&version=6&ts=%s&nonce=%s&appid=oeVkj2lYFGnJu5XUtWisfW4utiN4u9Mq&imei=%s&os=iOS&model=%s&romVersion=%s&appVersion=%s'.format(
        api_region, user_details['user']['apikey'],
        str(int(time.time())), ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(8)), imei, model, romVersion)
    r = requests.get(url, headers=headers)
    devices = r.json()

    return json.dumps(devices, indent=2, sort_keys=True)


def clean_data(data):
    data = re.sub(r'"phoneNumber": ".*"', '"phoneNumber": "[hidden]",', data)
    data = re.sub(r'"name": ".*"', '"name": "[hidden]",', data)
    data = re.sub(r'"ip": ".*",', '"ip": "[hidden]",', data)
    data = re.sub(r'"deviceid": ".*",', '"deviceid": "[hidden]",', data)
    data = re.sub(r'"_id": ".*",', '"_id": "[hidden]",', data)
    data = re.sub(r'"\w{2}:\w{2}:\w{2}:\w{2}:\w{2}:\w{2}"', '"xx:xx:xx:xx:xx:xx"', data)
    data = re.sub(r'"\w{8}-\w{4}-\w{4}-\w{4}-\w{12}"', '"xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"', data)
    data = re.sub(r'"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z"', '"xxxx-xx-xxxxx:xx:xx.xxx"', data)
    return data


if __name__ == "__main__":
    do_login()
    devices_json = get_devices()
    print(clean_data(devices_json))
