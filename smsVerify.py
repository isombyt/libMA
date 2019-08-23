"""
sms verify functions with demo
"""

import urllib2
import urllib
import hashlib
from Crypto.PublicKey import RSA
from Crypto.Cipher import DES
import binascii
import json
import string
import random
import time


DES_KEY = "w!o2a#r4e%g6i&n8(0)^_-==991000282"


def sign(strs):
    data = ("".join(strs)+"meiyumaclientserver5185f24b570b8").lower()
    return hashlib.md5(data).hexdigest().upper()

def des_encrypt(data, key=DES_KEY):
    length = str(len(data))
    head = ["","000","00","0"][len(length)] + length
    plaintext = head + data
    plaintext += "\x00" * (8 - (len(plaintext) % 8))
    cipher = DES.new(key=key[:8], mode=DES.MODE_ECB)
    return binascii.b2a_hex(cipher.encrypt(plaintext))

def connect(url,params = None ,headers={}):
    if not "USer-Agent" in headers:
        headers["User-Agent"] = "Apache-HttpClient/UNAVAILABLE (java 1.4)"
    if params:
        request = urllib2.Request(url,urllib.urlencode(params),headers)
    else:
        request = urllib2.Request(url,None,headers)
    response = urllib2.urlopen(request)
    return response.read()

def rsa(s):
    key = "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBANaXfXzDAON6GRKkk0G2FQVI/1MGjE7OEcDI8sv4EPhjhxon0a6oL//dDWuWwCSMUGfHY6xGwEvChO/LBY30Wo8CAwEAAQ=="
    cert = "-----BEGIN CERTIFICATE-----\n" + key + "\n-----END CERTIFICATE-----\n"
    publicKey = RSA.importKey(cert)
    m = publicKey.encrypt(s, None)
    return binascii.b2a_hex(m[0]).upper()

def iswhilelist(phoneNum):
    data = connect("http://api.mam.sdo.com/api.php?m=Index&a=iswhitelist&phoneid="+
                   phoneNum+"&sign="+sign([phoneNum]),None,{"APPID":1000,"CHANNEL":"M216"})
    return data

def randomstr(l):
    table = string.letters# + string.digits
    return "".join([random.choice(table) for i in range(l)])

def obtain(phoneNum):
    sign = rsa(randomstr(8))#rsa("00000000")
    sign = "D5797F184A5239BF80F9D65770E3B5E2FD2D54062D2CE8E02306697BD98705D5F84C4128088B9D0F998E578633DA9B7630FBA799E8BB082EEE0D3D73B804C0E4"
    url = "http://woa.sdo.com/woa/config/obtain.shtm?smsInterceptVersion=0"+\
    "&pubKeyVersion=1.0.1&model=ibbot&signature="+sign+\
    "&appid=991000282&areaid=1&clientversion=2.5.1&endpointos=android"
    data = connect(url)
    return data

def gen_android_id(android_id = None):
    if android_id == None:
        android_id = "".join([random.choice(string.hexdigits) for i in range(16)])
    android_id = android_id[:16]
    rtn = "A"+android_id+str(int(time.time()*1000))
    rtn += randomstr(32 - len(rtn))
    return rtn

def autologin_receive(phone,android_id):
    url = "http://woa.sdo.com/woa/autologin/receiveVerificationSms.shtm?"
    url += "phone=" + des_encrypt(phone)
    url += "&msg=" + "WOSL"+android_id+"-0-991000282-1"
    url += "&appid=991000282&areaid=1&clientversion=2.5.1&endpointos=android"
    data = connect(url)
    return data
    
def verifyClientEx(smsCode, android_id):
    key = randomstr(8)
    url = "http://woa.sdo.com/woa/autologin/verifyClientEx.shtm?"
    url += "signature=" + rsa(key)
    url += "&pubKeyVersion=1.0.1&uuid=" + android_id
    url += "&smsCode=" + des_encrypt(smsCode, key)
    url += "&imei=&appid=991000282&areaid=1&clientversion=2.5.1&endpointos=android"
    data = connect(url)
    return data
    
def checkwoasid(smsCode,android_id,phoneNum,guid,key):
    data = {
        'areaId': '1',
        'optype': 0,
        'uuid': des_encrypt(android_id+"|"+phoneNum, key),
        'clientVersion': '2.5.1',
        'hasSDCard': 1,
        'endpointOS': 'android',
        'smsCode': smsCode,
        'appId': '991000282',
        'guid': guid,
    }
    url = "http://api.mam.sdo.com/checkwoasid.php?"
    url += "woasid="+urllib.quote(json.dumps(data).encode("base64"))
    url += "&phoneid="+phoneNum
    data = connect(url)
    return data

def smsVerify(phoneNum,android_id = None):
    android_id = gen_android_id(android_id)
    data = json.loads(obtain(phoneNum))
    guid = data["guid"]
    key = data["key"]
    autologin_receive(phoneNum, android_id)
    def callback(smsCode):
        data = checkwoasid(smsCode,android_id,phoneNum,guid,key)
        return data
    return callback
