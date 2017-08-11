#!/usr/bin/python
# -*- coding: utf-8 -*-
# __author__ = "ihciah"

import os


def restart_tinc(original_ip, new_ip, interface):
    interface = str(interface).strip()
    new_ip = str(new_ip).strip()
    original_ip = str(original_ip).strip()
    valid_interfaces = ["tinc1", "tinc2"]
    if interface not in valid_interfaces or original_ip == new_ip:
        return "IP not changed or interface invalid."

    START_COMMAND = "/usr/bin/python /opt/trigger-tinc.py %s start" % interface
    STOP_COMMAND = "/usr/bin/python /opt/trigger-tinc.py %s stop" % interface

    if new_ip.startswith("10."):
        os.system(STOP_COMMAND)
        return "Tinc %s STOP." % interface
    else:
        os.system(START_COMMAND)
        return "Tinc %s START." % interface


def d1_onchange(original_ip, new_ip):
    # You can define your own onchange function
    return restart_tinc(original_ip, new_ip, "tinc1")


def d2_onchange(original_ip, new_ip):
    return restart_tinc(original_ip, new_ip, "tinc2")

DOMAIN_CONFIG = [
    {
        "domain": "domain1.ihc.im",
        "link": "/mydomain1",
        "encryption": ["otp", "AABBCCDDDDCCBBAA"],
        "onchange": d1_onchange
    },
    {
        "domain": "domain2.ihc.im",
        "link": "/mydomain2",
        "encryption": ["psk", "areyoualolicon"],
        "onchange": d2_onchange
    },
    {
        "domain": "domain3.ihc.im",
        "link": "/mydomain3",
        "encryption": "none"
    }
]

SERVER_CONFIG = {
    "http_port": 12345,
    "dns_port": 53,
    "ssl_crt": "/etc/ssl/ihc/crt",
    "ssl_key": "/etc/ssl/ihc/key"
}
