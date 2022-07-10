#!/usr/bin/env python3

from pwn import *
import requests
from func_timeout import func_set_timeout
import func_timeout

# from result import attack


attack_ip = ""
attack_ports = []
token = ""
event_hash = ""
flag_ip = ""


# 设定攻击超时时间，可自行调整，单位为s
@func_set_timeout(30)
def attack(p):
    pass


for port in attack_ports:
    try:
        p = remote("", 111)
        flag = attack(p)
        print(flag)
        d = {
            "flag": bytes(flag),
            "token": token,
            "event_hash": event_hash,
        }
        r = requests.post(flag_ip, data=d)
        print(r.text)
        p.close()
    except:
        continue
    finally:
        continue
