#!/usr/bin/env python3
"""
╔════════════════════════════════════════════════════════════════════════╗
║  Oculux v7.5 - Defensive Camera Verification (CamXploit-class, better) ║
║  Ranges · RTSP-first · Exploit-DB · Metasploit refs · Recon reports    ║
║                                                                        ║
║  pip install flask httpx dnspython                                     ║
║  Optional: masscan nmap hydra ffmpeg msfconsole searchsploit shodan    ║
╚════════════════════════════════════════════════════════════════════════╝
"""

from __future__ import annotations

import os
import sys
import json
import time
import random
import hashlib
import base64
import re
import io
import csv
import socket
import threading
import queue
import ipaddress
import sqlite3
import struct
import shutil
import subprocess
import tempfile
import logging
import ssl
import warnings
import itertools
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from collections import defaultdict
from typing import Any, Optional, Dict, List, Tuple, Set, Callable
from enum import Enum
import urllib.request
import urllib.parse
import urllib.error
import http.client
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed

# Optional deps with graceful fallback
try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False
    warnings.warn("httpx not installed; falling back to urllib. pip install httpx for async/concurrent HTTP.")

try:
    import dns.resolver
    HAS_DNS = True
except ImportError:
    HAS_DNS = False

try:
    import shodan
    HAS_SHODAN = True
except ImportError:
    HAS_SHODAN = False

from flask import Flask, render_template_string, jsonify, request, send_file
from werkzeug.security import safe_join

# ═══════════════════════════════════════════════════════════════
# LOGGING
# ═══════════════════════════════════════════════════════════════
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("oculux")

# ═══════════════════════════════════════════════════════════════
# CONSTANTS
# ═══════════════════════════════════════════════════════════════
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)

# SSL context that accepts self-signed certs (common for cameras)
SSL_CONTEXT = ssl.create_default_context()
SSL_CONTEXT.check_hostname = False
SSL_CONTEXT.verify_mode = ssl.CERT_NONE

# ═══════════════════════════════════════════════════════════════
# MODE CONFIG
# ═══════════════════════════════════════════════════════════════

class ScanMode(Enum):
    STEALTH = "stealth"
    QUIET = "quiet"
    MEDIUM = "medium"
    AGGRESSIVE = "aggressive"
    WAR = "war"
    NUKE = "nuke"

MODE_CONFIG: Dict[str, Dict[str, Any]] = {
    ScanMode.STEALTH.value: {
        "masscan": False,
        "nmap_flags": "-T2 --max-retries 1",
        "nmap_scripts": False,
        "max_creds": 16,
        "masscan_rate": 0,
        "protocols": ["rtsp", "onvif", "http"],
        "description": "Minimal noise, slowest",
    },
    ScanMode.QUIET.value: {
        "masscan": False,
        "nmap_flags": "-T3 --max-retries 1",
        "nmap_scripts": False,
        "max_creds": 32,
        "masscan_rate": 0,
        "protocols": ["rtsp", "onvif", "http", "ssdp"],
        "description": "Quiet local scans",
    },
    ScanMode.MEDIUM.value: {
        "masscan": True,
        "nmap_flags": "-T4 --max-retries 2",
        "nmap_scripts": False,
        "max_creds": 64,
        "masscan_rate": 5000,
        "protocols": ["rtsp", "onvif", "http", "ssdp", "coap"],
        "description": "Default balanced",
    },
    ScanMode.AGGRESSIVE.value: {
        "masscan": True,
        "nmap_flags": "-T4 --max-retries 3 --script default",
        "nmap_scripts": True,
        "max_creds": 96,
        "masscan_rate": 10000,
        "protocols": ["rtsp", "onvif", "http", "ssdp", "coap", "hls", "rtmp"],
        "description": "Scripts & versioning",
    },
    ScanMode.WAR.value: {
        "masscan": True,
        "nmap_flags": "-T5 --max-retries 3 --min-rate 100 --script default",
        "nmap_scripts": True,
        "max_creds": 128,
        "masscan_rate": 50000,
        "protocols": ["rtsp", "onvif", "http", "ssdp", "coap", "hls", "rtmp", "srt"],
        "description": "Broad coverage",
    },
    ScanMode.NUKE.value: {
        "masscan": True,
        "nmap_flags": "-T5 --max-retries 4 --min-rate 200 --script vuln,default",
        "nmap_scripts": True,
        "max_creds": 256,
        "masscan_rate": 100000,
        "protocols": ["rtsp", "onvif", "http", "ssdp", "coap", "hls", "rtmp", "srt"],
        "description": "Full sweep 1-65535",
    },
}

CORE_CAMERA_PORTS = [
    80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 443,
    554, 1554, 2554, 3554, 4554, 5554, 6554, 7554, 8554, 9554, 10554,
    1935, 5000, 5001, 5443, 7001, 7070, 7443,
    8000, 8001, 8008, 8080, 8081, 8082, 8083, 8084, 8085,
    8086, 8087, 8088, 8089, 8090, 8443, 8800, 8888, 8899,
    9000, 9001, 9443, 10000, 20000, 30000, 34567, 37777, 37778,
]

CAMERA_PORTS_BY_MODE: Dict[str, Any] = {
    ScanMode.STEALTH.value: [80, 443, 554, 8000, 8080, 8554],
    ScanMode.QUIET.value: [80, 81, 88, 443, 554, 8000, 8080, 8081, 8443, 8554, 37777],
    ScanMode.MEDIUM.value: CORE_CAMERA_PORTS[:28] + [8080, 8081, 8443, 8888, 9000, 34567, 37777],
    ScanMode.AGGRESSIVE.value: CORE_CAMERA_PORTS,
    ScanMode.WAR.value: CORE_CAMERA_PORTS,
    ScanMode.NUKE.value: "1-65535",
}

TLS_PORTS = {443, 5443, 7443, 8443, 9443}
BUILTIN_SCAN_MAX_HOSTS = 4096
SERVICE_PORTS: Dict[int, Tuple[str, str]] = {
    80: ("http", "Web interface"),
    443: ("https", "Secure web interface"),
    554: ("rtsp", "Real-Time Streaming Protocol"),
    1554: ("rtsp", "Alternate RTSP"),
    1935: ("rtmp", "Real-Time Messaging Protocol"),
    3702: ("onvif", "ONVIF discovery"),
    5000: ("http", "Alternate web interface"),
    8000: ("http", "Camera web/vendor service"),
    8008: ("http", "Alternate camera web service"),
    8080: ("http", "Alternate web interface"),
    8443: ("https", "Secure alternate web interface"),
    8554: ("rtsp", "Alternate RTSP"),
    8888: ("http", "Alternate web interface"),
    9000: ("camera", "Camera/DVR service"),
    34567: ("camera", "Generic DVR/NVR service"),
    37777: ("camera", "Dahua DVR/NVR service"),
    37778: ("camera", "Dahua alternate service"),
}

# ═══════════════════════════════════════════════════════════════
# VENDOR CATALOG
# ═══════════════════════════════════════════════════════════════

VENDOR_CATALOG: Dict[str, Dict[str, Any]] = {
    "Hikvision": {
        "fingerprint": ["Hikvision", "DNVRS-Webs", "dvrManager", "webCtrls"],
        "oui_prefixes": [
            "c0:56:e3", "44:19:b6", "28:57:be", "54:e4:bd",
            "3c:ef:8c", "a0:bd:1d", "b0:c5:ca", "e0:50:8b",
        ],
        "default_creds": [
            ("admin", "12345"), ("admin", "admin"), ("admin", "admin123"),
            ("admin", ""), ("admin", "hikvision"), ("admin", "888888"),
            ("admin", "666666"),
        ],
        "rtsp_paths": [
            "/Streaming/channels/{ch}",
            "/h264/ch{ch}/main/av_stream",
            "/ISAPI/Streaming/Channels/{ch}01",
            "/live/ch00_0",
        ],
        "http_paths": [
            "/ISAPI/System/deviceInfo",
            "/SDK/webLanguage",
            "/doc/page/login.asp",
            "/ISAPI/Security/userCheck",
        ],
        "snapshot_paths": [
            "/ISAPI/Streaming/channels/101/picture",
            "/Streaming/channels/1/picture",
        ],
        "model_patterns": [r"DS-2CD\w+", r"DS-2DF\w+", r"DS-2DE\w+", r"DS-2FE\w+", r"DS-2CE\w+"],
        "onvif_scopes": ["onvif://www.onvif.org/name/Hikvision"],
        "cves": [
            {
                "id": "CVE-2021-36260", "title": "Command Injection via webLanguage",
                "severity": "CRITICAL", "cvss": 9.8,
                "affected_models": ["DS-2CD", "DS-2DF", "DS-2DE", "DS-2XD", "DS-2FE", "DS-2CE"],
                "firmware_range": "<5.5.0",
                "exploit_path": "/SDK/webLanguage",
                "msf_module": "exploit/linux/http/hikvision_cve_2021_36260",
            },
            {
                "id": "CVE-2017-7921", "title": "Auth Bypass Hardcoded Creds",
                "severity": "CRITICAL", "cvss": 9.8,
                "affected_models": ["DS-2CD", "DS-2DF", "DS-2DE", "DS-2FE"],
                "firmware_range": "<5.3.0",
                "exploit_path": "/Security/users",
            },
            {
                "id": "CVE-2020-25078", "title": "Username Disclosure",
                "severity": "MEDIUM", "cvss": 5.3,
                "affected_models": ["DS-2CD", "DS-2DF"],
                "firmware_range": "any",
                "exploit_path": "/ISAPI/Security/userCheck",
            },
        ],
    },
    "Dahua": {
        "fingerprint": ["Dahua", "DHIPC-Webs", "MWEB", "web/Camera"],
        "oui_prefixes": ["3c:ef:8c", "40:2c:76", "a0:bd:1d", "d4:43:a8", "4c:11:bf", "38:af:d7"],
        "default_creds": [
            ("admin", "admin"), ("admin", "123456"), ("admin", ""),
            ("admin", "888888"), ("admin", "666666"), ("888888", "888888"),
        ],
        "rtsp_paths": [
            "/cam/realmonitor?channel={ch}&subtype=0",
            "/h264/ch{ch}/main/av_stream",
        ],
        "http_paths": [
            "/cgi-bin/magicBox.cgi",
            "/current_config/passwd",
            "/RPC2",
            "/cgi-bin/snapManager.cgi",
        ],
        "snapshot_paths": ["/cgi-bin/snapshot.cgi?channel={ch}"],
        "model_patterns": [r"IPC-HDW\w+", r"IPC-HFW\w+", r"NVR\w+", r"XVR\w+"],
        "onvif_scopes": ["onvif://www.onvif.org/name/Dahua"],
        "cves": [
            {
                "id": "CVE-2021-33044", "title": "Auth Bypass Special Characters",
                "severity": "CRITICAL", "cvss": 9.8,
                "affected_models": ["IPC-HDW", "IPC-HFW", "NVR", "XVR"],
                "firmware_range": "<2.800.0000000.18.R",
                "msf_module": "exploit/linux/http/dahua_cve_2021_33044",
            },
            {
                "id": "CVE-2021-33045", "title": "Auth Bypass Digest Auth",
                "severity": "CRITICAL", "cvss": 9.8,
                "affected_models": ["IPC", "NVR", "XVR"],
                "firmware_range": "<2.800.0000000.18.R",
            },
            {
                "id": "CVE-2020-25078", "title": "Password Disclosure",
                "severity": "CRITICAL", "cvss": 9.8,
                "affected_models": ["IPC-HDW", "IPC-HFW"],
                "firmware_range": "any",
                "exploit_path": "/current_config/passwd",
            },
        ],
    },
    "Axis": {
        "fingerprint": ["Axis", "AXIS", "VAPIX"],
        "oui_prefixes": ["00:40:8c", "ac:cc:8e", "b8:a4:4f"],
        "default_creds": [("root", "root"), ("root", ""), ("admin", "admin")],
        "rtsp_paths": ["/axis-media/media.amp"],
        "http_paths": [
            "/axis-cgi/mjpg/video.cgi",
            "/axis-cgi/jpg/image.cgi",
            "/axis-cgi/admin/param.cgi",
            "/view/viewer_index.shtml",
        ],
        "snapshot_paths": ["/axis-cgi/jpg/image.cgi"],
        "model_patterns": [r"M30\w*", r"P32\w*", r"Q35\w*"],
        "onvif_scopes": ["onvif://www.onvif.org/name/Axis"],
        "cves": [
            {
                "id": "CVE-2018-10660", "title": "VAPIX Unauthenticated Stream",
                "severity": "HIGH", "cvss": 7.5,
                "affected_models": ["M30", "P32", "Q35", "P34"],
                "firmware_range": "<10.9.1",
            },
        ],
    },
    "Foscam": {
        "fingerprint": ["Foscam", "IPCam"],
        "oui_prefixes": ["60:fa:cd", "b0:c5:54", "ec:17:2f"],
        "default_creds": [("admin", ""), ("admin", "admin"), ("admin", "12345")],
        "rtsp_paths": ["/videoMain", "/videoSub"],
        "http_paths": ["/cgi-bin/CGIProxy.fcgi?cmd=getSnapImage"],
        "snapshot_paths": ["/cgi-bin/CGIProxy.fcgi?cmd=snapPicture"],
        "model_patterns": [r"FI\w+", r"R2"],
        "onvif_scopes": [],
        "cves": [
            {
                "id": "CVE-2020-26063", "title": "RCE via CGI",
                "severity": "CRITICAL", "cvss": 9.8,
                "affected_models": ["FI9928P", "R2", "C1"],
                "firmware_range": "any",
            },
        ],
    },
    "Amcrest": {
        "fingerprint": ["Amcrest", "IPC-Webs"],
        "oui_prefixes": [],
        "default_creds": [("admin", "admin"), ("admin", "")],
        "rtsp_paths": ["/cam/realmonitor?channel=1&subtype=0"],
        "http_paths": ["/cgi-bin/magicBox.cgi"],
        "snapshot_paths": ["/cgi-bin/snapshot.cgi"],
        "model_patterns": [r"IP\w+M\w+"],
        "onvif_scopes": [],
        "cves": [],
    },
    "D-Link": {
        "fingerprint": ["D-Link", "DCS-", "DNR-"],
        "oui_prefixes": ["00:05:5d", "00:0d:88", "84:c9:b2", "90:8d:78"],
        "default_creds": [("admin", ""), ("admin", "admin")],
        "rtsp_paths": ["/live"],
        "http_paths": ["/config/getuser", "/video/mjpg.cgi"],
        "snapshot_paths": ["/image.jpg"],
        "model_patterns": [r"DCS-\w+", r"DNR-\w+"],
        "onvif_scopes": [],
        "cves": [
            {
                "id": "CVE-2020-25078", "title": "Credential Disclosure",
                "severity": "CRITICAL", "cvss": 9.8,
                "affected_models": ["DCS-", "DNR-"],
                "firmware_range": "any",
            },
        ],
    },
    "TP-Link": {
        "fingerprint": ["TP-Link", "Tapo"],
        "oui_prefixes": ["50:c7:bf", "60:32:b1", "ac:84:c6"],
        "default_creds": [("admin", "admin"), ("admin", "")],
        "rtsp_paths": ["/stream1", "/stream2"],
        "http_paths": ["/stream1"],
        "snapshot_paths": [],
        "model_patterns": [r"Tapo\s+\w+"],
        "onvif_scopes": [],
        "cves": [],
    },
    "Reolink": {
        "fingerprint": ["Reolink", "reolink", "RLN", "RLC"],
        "oui_prefixes": ["ec:71:db", "3c:84:6a", "b4:6d:83"],
        "default_creds": [("admin", ""), ("admin", "admin"), ("admin", "123456")],
        "rtsp_paths": ["/h264Preview_01_main", "/h264Preview_01_sub", "/stream1", "/stream2"],
        "http_paths": ["/api.cgi", "/cgi-bin/api.cgi", "/login.cgi"],
        "snapshot_paths": ["/cgi-bin/api.cgi?cmd=Snap&channel=0"],
        "model_patterns": [r"RLC-\w+", r"RLN\w+", r"Reolink\s+\w+"],
        "onvif_scopes": ["onvif://www.onvif.org/name/Reolink"],
        "cves": [
            {
                "id": "CVE-2023-27253", "title": "Unauthenticated RCE via api.cgi",
                "severity": "CRITICAL", "cvss": 9.8,
                "affected_models": ["RLC-410", "RLC-510", "RLC-520", "RLN8"],
                "firmware_range": "<3.0.0.136",
                "exploit_path": "/cgi-bin/api.cgi",
            },
            {
                "id": "CVE-2021-40847", "title": "Command Injection in api.cgi",
                "severity": "CRITICAL", "cvss": 9.8,
                "affected_models": ["RLC-410", "RLC-510", "RLC-520"],
                "firmware_range": "<3.0.0.136",
                "exploit_path": "/cgi-bin/api.cgi",
            },
        ],
    },
    "Vivotek": {
        "fingerprint": ["Vivotek", "VIVOTEK", "Network Camera"],
        "oui_prefixes": ["00:02:d1", "00:0f:7c", "00:40:8c"],
        "default_creds": [("root", "root"), ("admin", "admin"), ("root", "")],
        "rtsp_paths": ["/live.sdp", "/h264", "/video1.mjpg"],
        "http_paths": ["/cgi-bin/admin/getparam.cgi", "/cgi-bin/viewer/video.jpg"],
        "snapshot_paths": ["/cgi-bin/viewer/video.jpg"],
        "model_patterns": [r"IP\w+", r"FD\w+", r"FE\w+", r"SD\w+"],
        "onvif_scopes": ["onvif://www.onvif.org/name/Vivotek"],
        "cves": [
            {
                "id": "CVE-2020-11458", "title": "Path Traversal in getparam.cgi",
                "severity": "HIGH", "cvss": 7.5,
                "affected_models": ["FD816A", "FD816B", "FE8171", "SD9364"],
                "firmware_range": "<0100a",
                "exploit_path": "/cgi-bin/admin/getparam.cgi",
            },
            {
                "id": "CVE-2018-11529", "title": "RCE via CGI",
                "severity": "CRITICAL", "cvss": 9.8,
                "affected_models": ["FD816A", "FD816B", "FE8171"],
                "firmware_range": "any",
            },
        ],
    },
    "Uniview": {
        "fingerprint": ["Uniview", "UNV", "unv", "IPC-Webs"],
        "oui_prefixes": ["00:12:12", "00:1c:27", "00:1c:28"],
        "default_creds": [("admin", "admin"), ("admin", "123456"), ("admin", "")],
        "rtsp_paths": ["/live/ch0", "/media/video1", "/h264/ch1/main/av_stream"],
        "http_paths": ["/cgi-bin/magicBox.cgi", "/LAPI/V1.0/System/DeviceInfo"],
        "snapshot_paths": ["/cgi-bin/snapshot.cgi"],
        "model_patterns": [r"IPC\w+", r"NVR\w+", r"XVR\w+"],
        "onvif_scopes": ["onvif://www.onvif.org/name/Uniview"],
        "cves": [
            {
                "id": "CVE-2020-25078", "title": "Credential Disclosure",
                "severity": "CRITICAL", "cvss": 9.8,
                "affected_models": ["IPC", "NVR", "XVR"],
                "firmware_range": "any",
                "exploit_path": "/cgi-bin/magicBox.cgi",
            },
        ],
    },
    "Bosch": {
        "fingerprint": ["Bosch", "BOSCH", "VIDOS", "BVIP"],
        "oui_prefixes": ["00:07:5f", "00:0c:ce", "00:1c:57"],
        "default_creds": [("service", "service"), ("admin", "admin"), ("root", "root")],
        "rtsp_paths": ["/rtsp_tunnel", "/live", "/h264"],
        "http_paths": ["/cgi-bin/video.jpg", "/record/current.jpg"],
        "snapshot_paths": ["/cgi-bin/video.jpg"],
        "model_patterns": [r"DINION\s+\w+", r"AUTODOME\s+\w+", r"FLEXIDOME\s+\w+"],
        "onvif_scopes": ["onvif://www.onvif.org/name/Bosch"],
        "cves": [
            {
                "id": "CVE-2020-6770", "title": "RCE in BVIP",
                "severity": "CRITICAL", "cvss": 9.8,
                "affected_models": ["DINION", "AUTODOME", "FLEXIDOME"],
                "firmware_range": "<7.85",
            },
        ],
    },
    "Sony": {
        "fingerprint": ["Sony", "SNC-", "SNC"],
        "oui_prefixes": ["00:0c:ce", "00:1c:13", "00:1c:14"],
        "default_creds": [("admin", "admin"), ("root", "root"), ("admin", "")],
        "rtsp_paths": ["/media/video1", "/h264", "/live"],
        "http_paths": ["/cgi-bin/param.cgi", "/command/inquiry.cgi"],
        "snapshot_paths": ["/cgi-bin/param.cgi?action=snapshot"],
        "model_patterns": [r"SNC-\w+"],
        "onvif_scopes": ["onvif://www.onvif.org/name/Sony"],
        "cves": [
            {
                "id": "CVE-2020-25078", "title": "Credential Disclosure",
                "severity": "CRITICAL", "cvss": 9.8,
                "affected_models": ["SNC-"],
                "firmware_range": "any",
            },
        ],
    },
    "Panasonic": {
        "fingerprint": ["Panasonic", "PANASONIC", "WV-", "BB-HCM"],
        "oui_prefixes": ["00:80:f0", "00:01:38", "00:0c:ce"],
        "default_creds": [("admin", "12345"), ("admin", "admin"), ("root", "root")],
        "rtsp_paths": ["/h264", "/live", "/mjpeg"],
        "http_paths": ["/cgi-bin/camctrl", "/nphMotionJpeg"],
        "snapshot_paths": ["/SnapshotJPEG?Resolution=640x480"],
        "model_patterns": [r"WV-\w+", r"BB-HCM\w+"],
        "onvif_scopes": ["onvif://www.onvif.org/name/Panasonic"],
        "cves": [
            {
                "id": "CVE-2020-25078", "title": "Credential Disclosure",
                "severity": "CRITICAL", "cvss": 9.8,
                "affected_models": ["WV-", "BB-HCM"],
                "firmware_range": "any",
            },
        ],
    },
    "Samsung": {
        "fingerprint": ["Samsung", "SAMSUNG", "SNH-", "SNP-", "SND-"],
        "oui_prefixes": ["00:0c:6e", "00:1c:43", "00:1c:44"],
        "default_creds": [("admin", "4321"), ("admin", "admin"), ("root", "root")],
        "rtsp_paths": ["/profile1", "/profile2", "/live"],
        "http_paths": ["/cgi-bin/video.cgi", "/cgi-bin/main.cgi"],
        "snapshot_paths": ["/cgi-bin/video.cgi?msubmenu=snapshot"],
        "model_patterns": [r"SNH-\w+", r"SNP-\w+", r"SND-\w+"],
        "onvif_scopes": ["onvif://www.onvif.org/name/Samsung"],
        "cves": [
            {
                "id": "CVE-2020-25078", "title": "Credential Disclosure",
                "severity": "CRITICAL", "cvss": 9.8,
                "affected_models": ["SNH-", "SNP-", "SND-"],
                "firmware_range": "any",
            },
        ],
    },
    "Geovision": {
        "fingerprint": ["Geovision", "GeoVision", "GV-"],
        "oui_prefixes": ["00:0c:ce", "00:1c:13"],
        "default_creds": [("admin", "admin"), ("admin", ""), ("root", "root")],
        "rtsp_paths": ["/live", "/h264", "/video1"],
        "http_paths": ["/cgi-bin/video.cgi", "/cgi-bin/control.cgi"],
        "snapshot_paths": ["/cgi-bin/video.cgi?msubmenu=snapshot"],
        "model_patterns": [r"GV-\w+"],
        "onvif_scopes": ["onvif://www.onvif.org/name/Geovision"],
        "cves": [
            {
                "id": "CVE-2020-25078", "title": "Credential Disclosure",
                "severity": "CRITICAL", "cvss": 9.8,
                "affected_models": ["GV-"],
                "firmware_range": "any",
            },
        ],
    },
    "ACTi": {
        "fingerprint": ["ACTi", "ACTi", "ACM-", "ACD-"],
        "oui_prefixes": ["00:0c:ce", "00:1c:13"],
        "default_creds": [("admin", "admin"), ("admin", ""), ("root", "root")],
        "rtsp_paths": ["/live", "/h264", "/video1"],
        "http_paths": ["/cgi-bin/video.cgi", "/cgi-bin/control.cgi"],
        "snapshot_paths": ["/cgi-bin/video.cgi?msubmenu=snapshot"],
        "model_patterns": [r"ACM-\w+", r"ACD-\w+"],
        "onvif_scopes": ["onvif://www.onvif.org/name/ACTi"],
        "cves": [
            {
                "id": "CVE-2020-25078", "title": "Credential Disclosure",
                "severity": "CRITICAL", "cvss": 9.8,
                "affected_models": ["ACM-", "ACD-"],
                "firmware_range": "any",
            },
        ],
    },
    "Mobotix": {
        "fingerprint": ["Mobotix", "MOBOTIX", "Mx"],
        "oui_prefixes": ["00:0c:ce", "00:1c:13"],
        "default_creds": [("admin", "meinsm"), ("admin", "admin"), ("root", "root")],
        "rtsp_paths": ["/control/faststream.jpg", "/cgi-bin/faststream.jpg"],
        "http_paths": ["/control/userimage.html", "/cgi-bin/readimage.cgi"],
        "snapshot_paths": ["/cgi-bin/readimage.cgi"],
        "model_patterns": [r"Mx\w+", r"M\d+"],
        "onvif_scopes": ["onvif://www.onvif.org/name/Mobotix"],
        "cves": [
            {
                "id": "CVE-2020-25078", "title": "Credential Disclosure",
                "severity": "CRITICAL", "cvss": 9.8,
                "affected_models": ["Mx", "M"],
                "firmware_range": "any",
            },
        ],
    },
    "Generic-RTSP": {
        "fingerprint": ["rtsp", "RTSP"],
        "oui_prefixes": [],
        "default_creds": [("", ""), ("admin", "admin"), ("admin", "")],
        "rtsp_paths": ["/live", "/h264", "/stream", "/mjpeg"],
        "http_paths": ["/", "/video", "/live", "/snapshot"],
        "snapshot_paths": ["/snapshot", "/image.jpg"],
        "model_patterns": [],
        "onvif_scopes": [],
        "cves": [],
    },
}

COMMON_PASSWORDS: List[str] = [
    "123456", "password", "12345678", "qwerty", "123456789", "12345",
    "1234", "111111", "1234567", "dragon", "123123", "abc123",
    "football", "monkey", "letmein", "shadow", "master", "696969",
    "654321", "admin", "admin123", "root", "pass", "pass123",
    "camera", "security", "surveillance", "cctv", "hikvision", "dahua",
    "888888", "666666", "000000", "changeme", "default", "guest",
    "user", "test", "welcome", "password1", "password123",
]

# ═══════════════════════════════════════════════════════════════
# UTILITY
# ═══════════════════════════════════════════════════════════════

def find_tool(name: str) -> Optional[str]:
    """Find a tool binary on the system. Returns path or None."""
    return shutil.which(name)


def parse_ip_range(value: str) -> Optional[Tuple[ipaddress.IPv4Address, ipaddress.IPv4Address]]:
    """Parse start-end IP ranges: 192.168.1.1-192.168.1.50 or 192.168.1.1-50."""
    value = value.strip()
    if "-" not in value or "/" in value or value.upper().startswith("AS"):
        return None
    # Avoid treating host:port as a range
    if re.fullmatch(r".+:\d{1,5}", value) and value.count(":") == 1 and "-" not in value.split(":")[0]:
        return None
    left, right = value.rsplit("-", 1)
    left, right = left.strip(), right.strip()
    try:
        start = ipaddress.IPv4Address(left)
    except ValueError:
        return None
    try:
        if re.fullmatch(r"\d{1,3}", right):
            # Short form: 192.168.1.10-50
            parts = str(start).split(".")
            end = ipaddress.IPv4Address(".".join(parts[:3] + [right]))
        else:
            end = ipaddress.IPv4Address(right)
    except ValueError:
        return None
    if int(end) < int(start):
        raise ValueError(f"IP range end is before start: {value}")
    if int(end) - int(start) > 65535:
        raise ValueError("IP ranges are limited to 65536 addresses; use CIDR or Masscan for larger scopes")
    return start, end


def expand_ip_range_to_cidrs(start: ipaddress.IPv4Address, end: ipaddress.IPv4Address) -> List[str]:
    """Collapse an inclusive IPv4 range into the fewest CIDR blocks."""
    return [str(net) for net in ipaddress.summarize_address_range(start, end)]


def parse_target_spec(value: str) -> Tuple[str, Optional[int]]:
    """Parse CIDR, host, host:port, or leave ranges for expand_targets()."""
    value = value.strip()
    if not value:
        raise ValueError("Target cannot be empty")

    if value.startswith("["):
        match = re.fullmatch(r"\[([^]]+)](?::(\d+))?", value)
        if not match:
            raise ValueError(f"Invalid target: {value}")
        host, port_text = match.groups()
    elif "/" not in value and value.count(":") == 1:
        host, port_text = value.rsplit(":", 1)
        if not port_text.isdigit():
            host, port_text = value, None
    else:
        host, port_text = value, None

    port = int(port_text) if port_text else None
    if port is not None and not 1 <= port <= 65535:
        raise ValueError(f"Port must be between 1 and 65535: {port}")
    return host.strip(), port


def ports_for_mode(mode: str, custom_ports: Optional[Set[int]] = None) -> List[int]:
    configured = CAMERA_PORTS_BY_MODE.get(mode, CAMERA_PORTS_BY_MODE[ScanMode.MEDIUM.value])
    ports = list(CORE_CAMERA_PORTS if isinstance(configured, str) else configured)
    if custom_ports:
        ports.extend(custom_ports)
    return sorted(set(int(port) for port in ports if 1 <= int(port) <= 65535))


def http_get(url: str, timeout: float = 10.0, proxy_cfg: Optional[Dict[str, Any]] = None, domain: Optional[str] = None) -> bytes:
    """HTTP GET with optional proxy support. Uses httpx if available, else urllib."""
    # Extract domain for rate limiting if not provided
    if domain is None:
        try:
            domain = urllib.parse.urlparse(url).netloc.split(':')[0]
        except Exception:
            domain = "global"

    rate_limiter.wait(domain)

    if HAS_HTTPX:
        proxies = None
        if proxy_cfg and proxy_cfg.get("active"):
            proxy_url = proxy_cfg["url"]
            proxies = {
                "http://": proxy_url,
                "https://": proxy_url,
            }
        transport = httpx.HTTPTransport(verify=SSL_CONTEXT)
        with httpx.Client(
            proxies=proxies,
            timeout=httpx.Timeout(timeout),
            headers={"User-Agent": USER_AGENT},
            transport=transport,
            follow_redirects=True,
        ) as client:
            try:
                resp = client.get(url)
                resp.raise_for_status()
                rate_limiter.report_success(domain)
                return resp.content
            except Exception:
                rate_limiter.report_failure(domain)
                raise
    else:
        req = urllib.request.Request(url)
        req.add_header("User-Agent", USER_AGENT)

        handlers = []
        if proxy_cfg and proxy_cfg.get("active"):
            handlers.append(urllib.request.ProxyHandler({proxy_cfg["type"]: proxy_cfg["url"]}))

        # Add HTTPS handler with custom SSL context for self-signed certs
        handlers.append(urllib.request.HTTPSHandler(context=SSL_CONTEXT))
        opener = urllib.request.build_opener(*handlers)

        try:
            with opener.open(req, timeout=timeout) as resp:
                rate_limiter.report_success(domain)
                return resp.read()
        except urllib.error.HTTPError as e:
            if e.code in (429, 500, 502, 503, 504):
                rate_limiter.report_failure(domain)
            else:
                rate_limiter.report_success(domain)
            raise
        except Exception:
            rate_limiter.report_failure(domain)
            raise


async def async_http_get(
    client: httpx.AsyncClient, url: str, timeout: float = 10.0
) -> Optional[httpx.Response]:
    """Async HTTP GET using httpx. Returns None on failure.

    NOTE: When creating the AsyncClient, pass:
        transport=httpx.AsyncHTTPTransport(verify=SSL_CONTEXT)
    to ensure self-signed certs are accepted.
    """
    if not HAS_HTTPX:
        return None
    try:
        resp = await client.get(url, timeout=timeout)
        return resp
    except httpx.HTTPError as exc:
        logger.debug("HTTP error for %s: %s", url, exc)
        return None


# ═══════════════════════════════════════════════════════════════
# SCOPE MANAGER
# ═══════════════════════════════════════════════════════════════

@dataclass
class ScopeManager:
    cidrs: List[str] = field(default_factory=list)
    domains: List[str] = field(default_factory=list)
    asns: List[str] = field(default_factory=list)
    _resolved: Set[str] = field(default_factory=set, repr=False)
    _dirty: bool = True

    def add_cidr(self, cidr: str) -> None:
        self.cidrs.append(cidr)
        self._dirty = True

    def add_domain(self, domain: str) -> None:
        self.domains.append(domain)
        self._dirty = True

    def add_asn(self, asn: str) -> None:
        self.asns.append(asn)
        self._dirty = True

    def resolve(self) -> Set[str]:
        if not self._dirty:
            return self._resolved
        ips: Set[str] = set()
        for cidr in self.cidrs:
            try:
                net = ipaddress.ip_network(cidr, strict=False)
                hosts = itertools.islice(net.hosts(), 0, 65536)
                ips.update(str(h) for h in hosts)
            except ValueError as exc:
                logger.warning("Invalid CIDR %s: %s", cidr, exc)
        for domain in self.domains:
            try:
                results = socket.getaddrinfo(domain, None)
                for r in results:
                    ips.add(r[4][0])
            except socket.gaierror as exc:
                logger.debug("DNS resolution failed for %s: %s", domain, exc)
        for asn in self.asns:
            try:
                asn_clean = asn.lstrip("ASas")
                url = f"https://bgp.he.net/api/net/{asn_clean}"
                raw = http_get(url, timeout=10)
                data = json.loads(raw)
                for prefix in data.get("data", {}).get("prefixes", []):
                    cidr = prefix.get("prefix", "")
                    if cidr:
                        try:
                            net = ipaddress.ip_network(cidr, strict=False)
                            hosts = itertools.islice(net.hosts(), 0, 65536)
                            ips.update(str(h) for h in hosts)
                        except ValueError:
                            pass
            except Exception as exc:
                logger.debug("ASN lookup failed for %s: %s", asn, exc)
        self._resolved = ips
        self._dirty = False
        return ips

    def in_scope(self, ip: str) -> bool:
        if self._dirty:
            self.resolve()
        return ip in self._resolved

    def has_scope(self) -> bool:
        return bool(self.cidrs or self.domains or self.asns)

    def to_dict(self) -> Dict[str, Any]:
        self.resolve()
        return {
            "cidrs": self.cidrs,
            "domains": self.domains,
            "asns": self.asns,
            "resolved_count": len(self._resolved),
        }

    def clear(self) -> None:
        self.cidrs.clear()
        self.domains.clear()
        self.asns.clear()
        self._resolved.clear()
        self._dirty = True


# ═══════════════════════════════════════════════════════════════
# PROXY MANAGER
# ═══════════════════════════════════════════════════════════════

@dataclass
class ProxyManager:
    proxy_type: Optional[str] = None
    proxy_host: Optional[str] = None
    proxy_port: Optional[int] = None
    proxy_user: Optional[str] = None
    proxy_pass: Optional[str] = None

    def configure(self, ptype: str, host: str, port: int, user: Optional[str] = None, passwd: Optional[str] = None) -> None:
        self.proxy_type = ptype
        self.proxy_host = host
        self.proxy_port = port
        self.proxy_user = user
        self.proxy_pass = passwd

    def clear(self) -> None:
        self.proxy_type = None
        self.proxy_host = None
        self.proxy_port = None
        self.proxy_user = None
        self.proxy_pass = None

    @property
    def active(self) -> bool:
        return self.proxy_type is not None

    @property
    def url(self) -> Optional[str]:
        if not self.active:
            return None
        if self.proxy_user:
            return f"{self.proxy_type}://{self.proxy_user}:{self.proxy_pass}@{self.proxy_host}:{self.proxy_port}"
        return f"{self.proxy_type}://{self.proxy_host}:{self.proxy_port}"

    def get_config(self) -> Optional[Dict[str, Any]]:
        if not self.active:
            return None
        return {"active": True, "type": self.proxy_type, "url": self.url}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "active": self.active,
            "type": self.proxy_type,
            "host": self.proxy_host,
            "port": self.proxy_port,
        }


# ═══════════════════════════════════════════════════════════════
# RATE LIMITER — Token Bucket (no sleep inside lock)
# ═══════════════════════════════════════════════════════════════

class RateLimiter:
    def __init__(self, global_rps: float = 5.0, domain_rps: float = 2.0):
        self.global_rps = global_rps
        self.domain_rps = domain_rps
        self._global_tokens = 1.0
        self._global_last = time.monotonic()
        self._domain_tokens: Dict[str, float] = defaultdict(lambda: 1.0)
        self._domain_last: Dict[str, float] = defaultdict(float)
        self._domain_failures: Dict[str, int] = defaultdict(int)
        self._blocked: Set[str] = set()
        self._lock = threading.Lock()

    def _add_tokens(self, bucket: str = "global") -> None:
        now = time.monotonic()
        if bucket == "global":
            elapsed = now - self._global_last
            self._global_tokens = min(1.0, self._global_tokens + elapsed * self.global_rps)
            self._global_last = now
        else:
            elapsed = now - self._domain_last[bucket]
            failures = self._domain_failures.get(bucket, 0)
            backoff = 2.0 ** min(failures, 5)
            effective_rps = max(self.domain_rps / backoff, 0.1)
            self._domain_tokens[bucket] = min(1.0, self._domain_tokens[bucket] + elapsed * effective_rps)
            self._domain_last[bucket] = now

    def wait(self, domain: Optional[str] = None) -> None:
        while True:
            with self._lock:
                self._add_tokens("global")
                if self._global_tokens < 1.0:
                    need = (1.0 - self._global_tokens) / self.global_rps
                else:
                    need = 0.0
                    if domain:
                        self._add_tokens(domain)
                        if self._domain_tokens[domain] < 1.0:
                            failures = self._domain_failures.get(domain, 0)
                            backoff = 2.0 ** min(failures, 5)
                            effective_rps = max(self.domain_rps / backoff, 0.1)
                            need = (1.0 - self._domain_tokens[domain]) / effective_rps
                        else:
                            self._global_tokens -= 1.0
                            self._domain_tokens[domain] -= 1.0
                            return
                    else:
                        self._global_tokens -= 1.0
                        return
            time.sleep(max(need, 0.01))

    def report_failure(self, domain: str) -> None:
        with self._lock:
            self._domain_failures[domain] += 1
            if self._domain_failures[domain] >= 10:
                self._blocked.add(domain)

    def report_success(self, domain: str) -> None:
        with self._lock:
            self._domain_failures[domain] = max(0, self._domain_failures[domain] - 1)

    def is_blocked(self, domain: str) -> bool:
        return domain in self._blocked


# ═══════════════════════════════════════════════════════════════
# DATABASE
# ═══════════════════════════════════════════════════════════════

class Database:
    def __init__(self, path: str = "oculux_v7.db"):
        self.path = path
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.lock = threading.Lock()
        self._init_schema()

    def _init_schema(self) -> None:
        cursor = self.conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS assets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                asset_hash TEXT UNIQUE NOT NULL,
                primary_ip TEXT,
                primary_port INTEGER,
                vendor TEXT,
                model TEXT,
                firmware TEXT,
                camera_type TEXT,
                confidence REAL DEFAULT 0,
                confidence_reasons TEXT,
                classification TEXT,
                access_level TEXT DEFAULT 'unknown',
                has_password INTEGER DEFAULT 0,
                status TEXT DEFAULT 'open',
                auth_user TEXT,
                auth_pass_hash TEXT,
                country TEXT,
                city TEXT,
                latitude REAL,
                longitude REAL,
                org TEXT,
                asn TEXT,
                oui TEXT,
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_verified TIMESTAMP,
                verify_count INTEGER DEFAULT 0,
                decay_score REAL DEFAULT 1.0,
                next_recheck TIMESTAMP,
                discovery_source TEXT,
                tags TEXT,
                thumbnail TEXT
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS services (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                asset_id INTEGER NOT NULL,
                ip TEXT NOT NULL,
                port INTEGER NOT NULL,
                protocol TEXT,
                service_type TEXT,
                banner TEXT,
                http_title TEXT,
                paths TEXT,
                cves TEXT,
                cve_confidence TEXT,
                onvif_data TEXT,
                rtsp_url TEXT,
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(ip, port),
                FOREIGN KEY (asset_id) REFERENCES assets(id)
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS vulns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                vendor TEXT,
                cve_id TEXT UNIQUE,
                title TEXT,
                severity TEXT,
                cvss REAL,
                description TEXT,
                affected_models TEXT,
                firmware_range TEXT,
                exploit_path TEXT,
                msf_module TEXT
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT,
                engine TEXT,
                mode TEXT,
                start_time TIMESTAMP,
                end_time TIMESTAMP,
                assets_found INTEGER DEFAULT 0,
                vulnerable INTEGER DEFAULT 0
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS blocklist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT UNIQUE NOT NULL,
                reason TEXT,
                added TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS jobs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                asset_id INTEGER,
                tool TEXT,
                status TEXT DEFAULT 'pending',
                started TIMESTAMP,
                finished TIMESTAMP,
                result TEXT
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                asset_id INTEGER NOT NULL,
                cve_id TEXT NOT NULL,
                title TEXT,
                description TEXT,
                severity TEXT,
                cvss REAL,
                assessment TEXT,
                confidence INTEGER DEFAULT 0,
                evidence TEXT,
                remediation TEXT,
                reference_urls TEXT,
                exploitdb_refs TEXT,
                metasploit_modules TEXT,
                known_exploited INTEGER DEFAULT 0,
                checked TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(asset_id, cve_id),
                FOREIGN KEY (asset_id) REFERENCES assets(id)
            )
        """)
        self.conn.commit()
        self._populate_vulns()

    def _populate_vulns(self) -> None:
        cursor = self.conn.cursor()
        for vendor, data in VENDOR_CATALOG.items():
            for cve in data.get("cves", []):
                try:
                    cursor.execute(
                        "INSERT OR IGNORE INTO vulns VALUES (NULL,?,?,?,?,?,?,?,?,?,?)",
                        (
                            vendor, cve["id"], cve["title"], cve["severity"],
                            cve["cvss"], cve.get("description", ""),
                            json.dumps(cve.get("affected_models", [])),
                            cve.get("firmware_range", "any"),
                            cve.get("exploit_path", ""),
                            cve.get("msf_module", ""),
                        ),
                    )
                except sqlite3.Error as exc:
                    logger.debug("Vuln insert error: %s", exc)
        self.conn.commit()

    @staticmethod
    def _compute_asset_hash(ip: str, vendor: Optional[str] = None, model: Optional[str] = None, mac: Optional[str] = None) -> str:
        # MAC is the most stable identifier for physical devices
        if mac and mac.strip() and mac.lower() not in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff", ""):
            return hashlib.sha256(f"mac:{mac.lower().strip()}".encode()).hexdigest()[:16]
        # Fallback: IP + vendor + model (less stable due to DHCP)
        parts = [ip]
        if vendor:
            parts.append(vendor.lower().strip())
        if model:
            parts.append(model.lower().strip())
        return hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]

    def is_blocked(self, ip: str) -> bool:
        cursor = self.conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM blocklist WHERE ip=?", (ip,))
        return cursor.fetchone()[0] > 0

    def add_to_blocklist(self, ip: str, reason: str = "opt-out") -> None:
        with self.lock:
            cursor = self.conn.cursor()
            cursor.execute(
                "INSERT OR REPLACE INTO blocklist (ip, reason) VALUES (?, ?)",
                (ip, reason),
            )
            self.conn.commit()

    def get_blocklist(self) -> List[Dict[str, Any]]:
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM blocklist")
        cols = [d[0] for d in cursor.description]
        return [dict(zip(cols, row)) for row in cursor.fetchall()]

    def upsert_asset(self, data: Dict[str, Any], scope_mgr: ScopeManager) -> Optional[int]:
        with self.lock:
            cursor = self.conn.cursor()
            ip = data.get("ip") or data.get("host", "")
            vendor = data.get("vendor")
            model = data.get("model")
            mac = data.get("mac")

            cursor.execute("SELECT COUNT(*) FROM blocklist WHERE ip=?", (ip,))
            if cursor.fetchone()[0] > 0:
                return None

            if scope_mgr.has_scope() and not scope_mgr.in_scope(ip):
                return None

            asset_hash = self._compute_asset_hash(ip, vendor, model, mac)
            cursor.execute("SELECT id FROM assets WHERE asset_hash=?", (asset_hash,))
            existing = cursor.fetchone()

            if existing:
                asset_id = existing[0]
                update_fields = []
                update_values = []
                for field in [
                    "vendor", "model", "firmware", "camera_type", "confidence",
                    "confidence_reasons", "classification", "access_level",
                    "has_password", "status", "auth_user", "country", "city",
                    "latitude", "longitude", "org", "asn", "oui", "tags",
                    "thumbnail",
                ]:
                    if field in data and data[field] is not None:
                        update_fields.append(f"{field}=?")
                        update_values.append(data[field])
                if "auth_pass" in data:
                    auth_pass = data.get("auth_pass", "")
                    auth_pass_hash = hashlib.sha256(auth_pass.encode()).hexdigest()[:16] if auth_pass else None
                    update_fields.append("auth_pass_hash=?")
                    update_values.append(auth_pass_hash)
                update_fields.extend([
                    "last_seen=CURRENT_TIMESTAMP",
                    "verify_count=verify_count+1",
                    "decay_score=1.0",
                    "last_verified=CURRENT_TIMESTAMP",
                ])
                update_fields.append("primary_ip=COALESCE(NULLIF(primary_ip,''),?)")
                update_values.append(ip)
                update_values.append(asset_hash)
                cursor.execute(
                    f"UPDATE assets SET {','.join(update_fields)} WHERE asset_hash=?",
                    update_values,
                )
            else:
                auth_pass = data.get("auth_pass", "")
                auth_pass_hash = hashlib.sha256(auth_pass.encode()).hexdigest()[:16] if auth_pass else None
                cursor.execute(
                    """INSERT INTO assets (
                        asset_hash, primary_ip, primary_port, vendor, model,
                        firmware, camera_type, confidence, confidence_reasons,
                        classification, access_level, has_password, status,
                        auth_user, auth_pass_hash, country, city, latitude,
                        longitude, org, asn, oui, discovery_source, tags,
                        thumbnail, next_recheck
                    ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,datetime('now','+7 days'))""",
                    (
                        asset_hash, ip, data.get("port"), vendor, model,
                        data.get("firmware"), data.get("camera_type"),
                        data.get("confidence", 0),
                        json.dumps(data.get("confidence_reasons", {})),
                        data.get("classification", "unknown"),
                        data.get("access_level", "unknown"),
                        data.get("has_password", 0),
                        data.get("status", "open"),
                        data.get("auth_user"), auth_pass_hash,
                        data.get("country"), data.get("city"),
                        data.get("latitude"), data.get("longitude"),
                        data.get("org"), data.get("asn"), data.get("oui"),
                        data.get("discovery_source"),
                        json.dumps(data.get("tags", [])),
                        data.get("thumbnail"),
                    ),
                )
                asset_id = cursor.lastrowid

            self.conn.commit()
            return asset_id

    def upsert_service(self, asset_id: int, data: Dict[str, Any]) -> int:
        with self.lock:
            cursor = self.conn.cursor()
            ip = data.get("ip", "")
            port = data.get("port", 0)
            cursor.execute("SELECT id FROM services WHERE ip=? AND port=?", (ip, port))
            existing = cursor.fetchone()

            if existing:
                svc_id = existing[0]
                update_fields = []
                update_values = []
                for field in [
                    "protocol", "service_type", "banner", "http_title",
                    "paths", "cves", "cve_confidence", "onvif_data", "rtsp_url",
                ]:
                    if field in data and data[field] is not None:
                        update_fields.append(f"{field}=?")
                        update_values.append(data[field])
                update_fields.append("last_seen=CURRENT_TIMESTAMP")
                update_values.append(svc_id)
                cursor.execute(
                    f"UPDATE services SET {','.join(update_fields)} WHERE id=?",
                    update_values,
                )
            else:
                cursor.execute(
                    """INSERT INTO services (
                        asset_id, ip, port, protocol, service_type, banner,
                        http_title, paths, cves, cve_confidence, onvif_data,
                        rtsp_url
                    ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        asset_id, ip, port, data.get("protocol"),
                        data.get("service_type"), data.get("banner"),
                        data.get("http_title"),
                        json.dumps(data.get("paths", [])),
                        json.dumps(data.get("cves", [])),
                        json.dumps(data.get("cve_confidence", {})),
                        json.dumps(data.get("onvif_data", {})),
                        data.get("rtsp_url"),
                    ),
                )
                svc_id = cursor.lastrowid

            self.conn.commit()
            return svc_id

    def get_assets(self, filters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        cursor = self.conn.cursor()
        query = "SELECT * FROM assets WHERE 1=1"
        params: List[Any] = []
        if filters:
            if filters.get("vendor"):
                query += " AND vendor=?"
                params.append(filters["vendor"])
            if filters.get("camera_type"):
                query += " AND camera_type=?"
                params.append(filters["camera_type"])
            if filters.get("access_level"):
                query += " AND access_level=?"
                params.append(filters["access_level"])
            if filters.get("status"):
                query += " AND status=?"
                params.append(filters["status"])
            if filters.get("search"):
                query += " AND (primary_ip LIKE ? OR vendor LIKE ? OR model LIKE ?)"
                s = f"%{filters['search']}%"
                params.extend([s, s, s])
            if filters.get("min_confidence"):
                query += " AND confidence>=?"
                params.append(float(filters["min_confidence"]))
        query += " ORDER BY confidence DESC, last_seen DESC LIMIT 500"
        cursor.execute(query, params)
        cols = [d[0] for d in cursor.description]
        return [dict(zip(cols, row)) for row in cursor.fetchall()]

    def get_asset(self, asset_id: int) -> Optional[Dict[str, Any]]:
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM assets WHERE id=?", (asset_id,))
        cols = [d[0] for d in cursor.description]
        row = cursor.fetchone()
        return dict(zip(cols, row)) if row else None

    def get_services(self, asset_id: int) -> List[Dict[str, Any]]:
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM services WHERE asset_id=?", (asset_id,))
        cols = [d[0] for d in cursor.description]
        return [dict(zip(cols, row)) for row in cursor.fetchall()]

    def replace_findings(self, asset_id: int, findings: List[Dict[str, Any]]) -> None:
        """Replace an asset's evidence-based vulnerability assessment."""
        with self.lock:
            cursor = self.conn.cursor()
            cursor.execute("DELETE FROM findings WHERE asset_id=?", (asset_id,))
            for finding in findings:
                cursor.execute(
                    """INSERT INTO findings (
                        asset_id, cve_id, title, description, severity, cvss,
                        assessment, confidence, evidence, remediation,
                        reference_urls, exploitdb_refs, metasploit_modules,
                        known_exploited
                    ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        asset_id, finding.get("cve_id"), finding.get("title"),
                        finding.get("description"), finding.get("severity"),
                        finding.get("cvss"), finding.get("assessment"),
                        finding.get("confidence", 0),
                        json.dumps(finding.get("evidence", [])),
                        finding.get("remediation"),
                        json.dumps(finding.get("reference_urls", [])),
                        json.dumps(finding.get("exploitdb_refs", [])),
                        json.dumps(finding.get("metasploit_modules", [])),
                        1 if finding.get("known_exploited") else 0,
                    ),
                )
            self.conn.commit()

    def get_findings(self, asset_id: int) -> List[Dict[str, Any]]:
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT * FROM findings WHERE asset_id=? ORDER BY known_exploited DESC, cvss DESC, cve_id",
            (asset_id,),
        )
        cols = [d[0] for d in cursor.description]
        findings = [dict(zip(cols, row)) for row in cursor.fetchall()]
        for finding in findings:
            for key in ("evidence", "reference_urls", "exploitdb_refs", "metasploit_modules"):
                try:
                    finding[key] = json.loads(finding.get(key) or "[]")
                except (TypeError, json.JSONDecodeError):
                    finding[key] = []
            finding["known_exploited"] = bool(finding.get("known_exploited"))
        return findings

    def get_stats(self) -> Dict[str, Any]:
        cursor = self.conn.cursor()
        stats: Dict[str, Any] = {}
        cursor.execute("SELECT COUNT(*) FROM assets")
        stats["total_assets"] = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM services")
        stats["total_services"] = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM assets WHERE status='vulnerable'")
        stats["vulnerable"] = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM assets WHERE has_password=0 AND status!='open'")
        stats["no_password"] = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM assets WHERE access_level='default'")
        stats["default_creds"] = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM assets WHERE access_level='needs_cracking'")
        stats["needs_cracking"] = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(DISTINCT vendor) FROM assets WHERE vendor IS NOT NULL")
        stats["unique_vendors"] = cursor.fetchone()[0]
        cursor.execute("SELECT AVG(confidence) FROM assets")
        stats["avg_confidence"] = round(cursor.fetchone()[0] or 0, 1)
        cursor.execute("SELECT COUNT(*) FROM assets WHERE decay_score < 0.5")
        stats["stale"] = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM assets WHERE last_verified > datetime('now','-7 days')")
        stats["fresh"] = cursor.fetchone()[0]
        cursor.execute("SELECT vendor, COUNT(*) FROM assets GROUP BY vendor ORDER BY COUNT(*) DESC")
        stats["by_vendor"] = dict(cursor.fetchall())
        cursor.execute("SELECT access_level, COUNT(*) FROM assets GROUP BY access_level ORDER BY COUNT(*) DESC")
        stats["by_access"] = dict(cursor.fetchall())
        cursor.execute("SELECT discovery_source, COUNT(*) FROM assets GROUP BY discovery_source ORDER BY COUNT(*) DESC")
        stats["by_source"] = dict(cursor.fetchall())
        cursor.execute("SELECT severity, COUNT(*) FROM vulns GROUP BY severity")
        stats["cve_severity"] = dict(cursor.fetchall())
        cursor.execute("SELECT COUNT(*) FROM vulns")
        stats["total_cves"] = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM findings")
        stats["assessed_findings"] = cursor.fetchone()[0]
        cursor.execute("SELECT country, COUNT(*) FROM assets WHERE country IS NOT NULL GROUP BY country ORDER BY COUNT(*) DESC LIMIT 10")
        stats["by_country"] = dict(cursor.fetchall())
        return stats

    def get_vulns(self, vendor: Optional[str] = None) -> List[Dict[str, Any]]:
        cursor = self.conn.cursor()
        if vendor:
            cursor.execute("SELECT * FROM vulns WHERE vendor=? ORDER BY cvss DESC", (vendor,))
        else:
            cursor.execute("SELECT * FROM vulns ORDER BY cvss DESC")
        cols = [d[0] for d in cursor.description]
        return [dict(zip(cols, row)) for row in cursor.fetchall()]

    def add_scan(self, data: Dict[str, Any]) -> None:
        with self.lock:
            cursor = self.conn.cursor()
            cursor.execute(
                "INSERT INTO scan_history VALUES (NULL,?,?,?,?,?,?,?)",
                (data["target"], data["engine"], data.get("mode", ""),
                 data["start_time"], data["end_time"],
                 data["assets_found"], data["vulnerable"]),
            )
            self.conn.commit()

    def add_job(self, asset_id: int, tool: str) -> int:
        with self.lock:
            cursor = self.conn.cursor()
            cursor.execute(
                "INSERT INTO jobs (asset_id, tool, status) VALUES (?,?,?)",
                (asset_id, tool, "pending"),
            )
            self.conn.commit()
            return cursor.lastrowid

    def update_job(self, job_id: int, **kwargs: Any) -> None:
        with self.lock:
            cursor = self.conn.cursor()
            for key, val in kwargs.items():
                cursor.execute(f"UPDATE jobs SET {key}=? WHERE id=?", (val, job_id))
            self.conn.commit()

    def get_jobs(self) -> List[Dict[str, Any]]:
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM jobs ORDER BY started DESC LIMIT 100")
        cols = [d[0] for d in cursor.description]
        return [dict(zip(cols, row)) for row in cursor.fetchall()]

    def compute_decay(self) -> None:
        with self.lock:
            cursor = self.conn.cursor()
            # Use strftime('%s', ...) which is standard SQLite, not julianday
            cursor.execute("""
                UPDATE assets SET decay_score =
                    MAX(0.1, 1.0 * EXP(-0.023 *
                    CAST((strftime('%s', 'now') - strftime('%s', last_verified)) / 86400.0 AS REAL)))
                WHERE last_verified IS NOT NULL
            """)
            cursor.execute("""
                UPDATE assets SET next_recheck =
                    CASE
                        WHEN decay_score < 0.5 THEN datetime('now', '+1 day')
                        WHEN decay_score < 0.8 THEN datetime('now', '+7 days')
                        ELSE datetime('now', '+30 days')
                    END
                WHERE next_recheck IS NULL OR next_recheck < datetime('now')
            """)
            self.conn.commit()

    def clear_all(self) -> None:
        with self.lock:
            cursor = self.conn.cursor()
            cursor.execute("DELETE FROM findings")
            cursor.execute("DELETE FROM services")
            cursor.execute("DELETE FROM assets")
            cursor.execute("DELETE FROM scan_history")
            cursor.execute("DELETE FROM jobs")
            self.conn.commit()

    def close(self) -> None:
        self.conn.close()


# ═══════════════════════════════════════════════════════════════
# CONFIDENCE SCORER — Fixed weights (sum to 100)
# ═══════════════════════════════════════════════════════════════

class ConfidenceScorer:
    WEIGHTS = {
        "banner_exact": 20, "banner_partial": 10, "oui_match": 15,
        "onvif_confirm": 20, "http_title": 10, "rtsp_ok": 30,
        "cert_cn": 5, "model_found": 10, "firmware_found": 5,
        "port_combo": 5, "ssdp_match": 5, "camera_signal": 20,
        "auth_challenge": 5,
    }

    @classmethod
    def score(cls, data: Dict[str, Any]) -> Tuple[int, Dict[str, str], str]:
        total = 0
        reasons: Dict[str, str] = {}
        vendor = data.get("vendor", "Unknown")
        banner = (data.get("banner") or "").lower()
        http_title = (data.get("http_title") or "").lower()
        port = data.get("port", 0)
        model = data.get("model", "")
        oui = data.get("oui", "")
        onvif = data.get("onvif_data", {})
        ssdp = data.get("ssdp_data", {})

        if vendor != "Unknown" and vendor.lower() in banner:
            total += cls.WEIGHTS["banner_exact"]
            reasons["banner_exact"] = f"'{vendor}' in banner"

        if oui and vendor in VENDOR_CATALOG:
            for prefix in VENDOR_CATALOG[vendor].get("oui_prefixes", []):
                if oui.lower().startswith(prefix.lower()):
                    total += cls.WEIGHTS["oui_match"]
                    reasons["oui_match"] = f"OUI {oui} matches {vendor}"
                    break

        if onvif:
            scopes = onvif.get("scopes", [])
            for known_scope in VENDOR_CATALOG.get(vendor, {}).get("onvif_scopes", []):
                if any(known_scope.lower() in s.lower() for s in scopes):
                    total += cls.WEIGHTS["onvif_confirm"]
                    reasons["onvif_confirm"] = f"ONVIF confirms {vendor}"
                    break

        if vendor != "Unknown" and vendor.lower() in http_title:
            total += cls.WEIGHTS["http_title"]
            reasons["http_title"] = f"Title contains '{vendor}'"

        if data.get("rtsp_ok"):
            total += cls.WEIGHTS["rtsp_ok"]
            reasons["rtsp_ok"] = "RTSP service positively identified"

        if data.get("camera_signal"):
            total += cls.WEIGHTS["camera_signal"]
            reasons["camera_signal"] = "Camera or video indicators found in service response"

        if data.get("auth_required"):
            total += cls.WEIGHTS["auth_challenge"]
            reasons["auth_challenge"] = "Service presents an authentication challenge"

        if model and model != "Unknown":
            total += cls.WEIGHTS["model_found"]
            reasons["model_found"] = f"Model '{model}' identified"

        if data.get("firmware"):
            total += cls.WEIGHTS["firmware_found"]
            reasons["firmware_found"] = f"Firmware {data['firmware']}"

        if port in (554, 8554, 37777, 34567):
            total += cls.WEIGHTS["port_combo"]
            reasons["port_combo"] = f"Port {port} is camera-typical"

        if ssdp:
            total += cls.WEIGHTS["ssdp_match"]
            reasons["ssdp_match"] = "SSDP discovery match"

        total = min(total, 100)

        if total >= 70:
            classification = "camera"
        elif total >= 40:
            classification = "likely_camera"
        elif total >= 20:
            classification = "possible_camera"
        else:
            classification = "unknown"

        return total, reasons, classification


# ═══════════════════════════════════════════════════════════════
# CVE MATCHER
# ═══════════════════════════════════════════════════════════════

class CVEMatcher:
    @classmethod
    def match(cls, vendor: str, model: Optional[str] = None, firmware: Optional[str] = None) -> Tuple[List[str], Dict[str, Any]]:
        if vendor not in VENDOR_CATALOG:
            return [], {}

        catalog_cves = VENDOR_CATALOG[vendor].get("cves", [])
        matched: List[str] = []
        confidence: Dict[str, Any] = {}

        for cve in catalog_cves:
            affected = cve.get("affected_models", [])
            fw_range = cve.get("firmware_range", "any")

            if not model or not affected:
                matched.append(cve["id"])
                confidence[cve["id"]] = {
                    "level": "vendor_only", "score": 30,
                    "reason": "Matched by vendor only",
                }
                continue

            model_matches = any(am.lower() in (model or "").lower() for am in affected)

            if model_matches:
                if fw_range == "any" or not firmware:
                    matched.append(cve["id"])
                    confidence[cve["id"]] = {
                        "level": "model_match", "score": 70,
                        "reason": f"Model '{model}' in affected list",
                    }
                else:
                    matched.append(cve["id"])
                    confidence[cve["id"]] = {
                        "level": "model_firmware", "score": 95,
                        "reason": "Model + firmware match",
                    }
            else:
                matched.append(cve["id"])
                confidence[cve["id"]] = {
                    "level": "vendor_only", "score": 30,
                    "reason": "Vendor match, model not in affected list",
                }

        return matched, confidence


# ═══════════════════════════════════════════════
# DEFENSIVE VULNERABILITY INTELLIGENCE
# ═══════════════════════════════════════════════

class ExploitDBCatalog:
    """Search the local Exploit-DB catalog without copying or executing exploits."""
    CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

    @classmethod
    def search(cls, cve_id: str) -> List[Dict[str, str]]:
        cve_id = (cve_id or "").upper()
        tool = find_tool("searchsploit")
        if not tool or not cls.CVE_RE.fullmatch(cve_id):
            return []
        try:
            result = subprocess.run(
                [tool, "--cve", cve_id.removeprefix("CVE-"), "--json"],
                capture_output=True, text=True, timeout=30,
            )
            data = json.loads(result.stdout or "{}")
        except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
            return []

        matches: List[Dict[str, str]] = []
        for key in ("RESULTS_EXPLOIT", "RESULTS_SHELLCODE"):
            for item in data.get(key, []) or []:
                edb_id = str(item.get("EDB-ID") or item.get("EDB_ID") or "").strip()
                title = str(item.get("Title") or item.get("title") or "Exploit-DB entry").strip()
                if not edb_id:
                    continue
                matches.append({
                    "id": edb_id,
                    "title": title,
                    "url": f"https://www.exploit-db.com/exploits/{edb_id}",
                })
        return matches[:10]


class MetasploitCatalog:
    """Correlate CVEs with installed Metasploit modules; never runs a module."""
    CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
    _index: Optional[Dict[str, Set[str]]] = None

    @classmethod
    def _build_local_index(cls) -> Dict[str, Set[str]]:
        index: Dict[str, Set[str]] = defaultdict(set)
        roots: List[Path] = []
        for raw in os.getenv("MSF_MODULE_PATH", "").split(os.pathsep):
            if raw:
                roots.append(Path(raw))
        roots.extend([
            Path("/usr/share/metasploit-framework/modules"),
            Path("/opt/metasploit-framework/embedded/framework/modules"),
        ])
        seen: Set[Path] = set()
        for root in roots:
            if not root.is_dir() or root in seen:
                continue
            seen.add(root)
            for module_file in root.rglob("*.rb"):
                try:
                    content = module_file.read_text(encoding="utf-8", errors="ignore")
                    rel = module_file.relative_to(root).with_suffix("").as_posix()
                except OSError:
                    continue
                ids = set(re.findall(r"\bCVE-(\d{4}-\d{4,})\b", content, re.IGNORECASE))
                ids.update(re.findall(
                    r"['\"]CVE['\"]\s*,\s*['\"](\d{4}-\d{4,})['\"]",
                    content, re.IGNORECASE,
                ))
                for suffix in ids:
                    index[f"CVE-{suffix}".upper()].add(rel)
        return index

    @classmethod
    def search(cls, cve_id: str) -> List[str]:
        cve_id = (cve_id or "").upper()
        if not cls.CVE_RE.fullmatch(cve_id):
            return []
        if cls._index is None:
            cls._index = cls._build_local_index()
        local = sorted(cls._index.get(cve_id, set()))
        if local:
            return local[:10]

        msfconsole = find_tool("msfconsole")
        if not msfconsole:
            return []
        try:
            result = subprocess.run(
                [msfconsole, "-q", "-x", f"search cve:{cve_id}; exit -y"],
                capture_output=True, text=True, timeout=60,
            )
        except (OSError, subprocess.TimeoutExpired):
            return []
        return sorted(set(re.findall(
            r"\b(?:exploit|auxiliary)/[A-Za-z0-9_./-]+", result.stdout or ""
        )))[:10]


class VulnerabilityIntelligence:
    """Build conservative, evidence-linked repair reports from NVD and local catalogs."""
    NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    @staticmethod
    def _norm(value: Any) -> str:
        return re.sub(r"[^a-z0-9]", "", str(value or "").lower())

    @classmethod
    def _cvss(cls, cve: Dict[str, Any]) -> Tuple[float, str]:
        metrics = cve.get("metrics") or {}
        for metric_name in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(metric_name) or []
            if not entries:
                continue
            entry = entries[0] or {}
            data = entry.get("cvssData") or {}
            try:
                score = float(data.get("baseScore") or 0)
            except (TypeError, ValueError):
                score = 0.0
            severity = str(data.get("baseSeverity") or entry.get("baseSeverity") or "UNKNOWN").upper()
            return score, severity
        return 0.0, "UNKNOWN"

    @classmethod
    def _nvd_results(cls, query: str) -> List[Dict[str, Any]]:
        params = urllib.parse.urlencode({"keywordSearch": query, "resultsPerPage": 30})
        raw = http_get(f"{cls.NVD_URL}?{params}", timeout=30, domain="services.nvd.nist.gov")
        data = json.loads(raw)
        return [entry.get("cve", {}) for entry in data.get("vulnerabilities", [])]

    @classmethod
    def _catalog_fallback(cls, vendor: str) -> List[Dict[str, Any]]:
        results = []
        for item in VENDOR_CATALOG.get(vendor, {}).get("cves", []):
            results.append({
                "id": item.get("id"),
                "descriptions": [{"lang": "en", "value": item.get("description") or item.get("title", "")}],
                "metrics": {"cvssMetricV31": [{
                    "cvssData": {"baseScore": item.get("cvss", 0), "baseSeverity": item.get("severity", "UNKNOWN")}
                }]},
                "references": [],
                "_catalog_title": item.get("title"),
                "_affected_models": item.get("affected_models", []),
            })
        return results

    @classmethod
    def assess(
        cls,
        asset: Dict[str, Any],
        services: List[Dict[str, Any]],
        progress: Optional[Callable[[str], None]] = None,
    ) -> List[Dict[str, Any]]:
        vendor = str(asset.get("vendor") or "").strip()
        model = str(asset.get("model") or "").strip()
        firmware = str(asset.get("firmware") or "").strip()
        if not vendor or vendor.lower() == "unknown":
            raise ValueError("Identify the camera vendor before running a CVE assessment")

        query = " ".join(part for part in (vendor, model) if part)
        if progress:
            progress(f"NVD: looking up {query}")
        nvd_error = ""
        try:
            candidates = cls._nvd_results(query)
        except Exception as exc:
            nvd_error = str(exc)
            candidates = []
        by_id = {str(cve.get("id") or "").upper(): cve for cve in candidates if cve.get("id")}
        for cve in cls._catalog_fallback(vendor):
            by_id.setdefault(str(cve.get("id") or "").upper(), cve)

        vendor_norm = cls._norm(vendor)
        model_norm = cls._norm(model)
        firmware_norm = cls._norm(firmware)
        service_evidence = [
            f"Observed {s.get('service_type') or s.get('protocol') or 'service'} on {s.get('ip')}:{s.get('port')}"
            for s in services[:8]
        ]
        findings: List[Dict[str, Any]] = []
        for cve_id, cve in by_id.items():
            descriptions = cve.get("descriptions") or []
            description = next(
                (str(d.get("value") or "") for d in descriptions if d.get("lang") == "en"),
                str(descriptions[0].get("value") or "") if descriptions else "",
            )
            cpe_text: List[str] = []

            def collect_cpes(node: Any) -> None:
                if isinstance(node, dict):
                    if node.get("criteria"):
                        cpe_text.append(str(node["criteria"]))
                    for value in node.values():
                        collect_cpes(value)
                elif isinstance(node, list):
                    for value in node:
                        collect_cpes(value)

            collect_cpes(cve.get("configurations") or [])
            haystack = cls._norm(" ".join([description, *cpe_text, " ".join(cve.get("_affected_models", []))]))
            vendor_hit = bool(vendor_norm and vendor_norm in haystack)
            model_hit = bool(model_norm and len(model_norm) >= 3 and model_norm in haystack)
            firmware_hit = bool(firmware_norm and len(firmware_norm) >= 3 and firmware_norm in haystack)

            evidence = list(service_evidence)
            if model_hit:
                evidence.append(f"Detected model '{model}' appears in NVD/CPE affected-product data")
            elif vendor_hit:
                evidence.append(f"Detected vendor '{vendor}' appears in NVD/CPE data; exact model was not verified")
            else:
                evidence.append(f"Local camera catalog associates {vendor} with this CVE; verify against the vendor advisory")
            if firmware:
                evidence.append(
                    f"Detected firmware '{firmware}' {'appears in' if firmware_hit else 'was not conclusively matched to'} the affected-version data"
                )

            if model_hit and firmware_hit:
                assessment, confidence = "likely affected — verify before remediation", 90
            elif model_hit:
                assessment, confidence = "potentially affected — firmware verification required", 75
            else:
                assessment, confidence = "review required — vendor-level match only", 35

            score, severity = cls._cvss(cve)
            refs = [str(ref.get("url")) for ref in (cve.get("references") or []) if ref.get("url")][:10]
            required_action = str(cve.get("cisaRequiredAction") or "").strip()
            remediation = required_action or (
                "Verify the exact model and firmware in the vendor advisory, update to the latest vendor-supported "
                "firmware, restrict camera management and streaming ports to trusted networks or a VPN, disable "
                "direct internet exposure, and rotate default or reused credentials."
            )
            title = str(cve.get("cisaVulnerabilityName") or cve.get("_catalog_title") or "").strip()
            if not title:
                title = (description.split(".", 1)[0] or cve_id)[:180]
            findings.append({
                "cve_id": cve_id,
                "title": title,
                "description": description,
                "severity": severity,
                "cvss": score,
                "assessment": assessment,
                "confidence": confidence,
                "evidence": evidence,
                "remediation": remediation,
                "reference_urls": refs,
                "exploitdb_refs": [],
                "metasploit_modules": [],
                "known_exploited": bool(cve.get("cisaExploitAdd")),
            })

        findings.sort(key=lambda item: (item["known_exploited"], item["cvss"], item["confidence"]), reverse=True)
        for finding in findings[:10]:
            if progress:
                progress(f"Catalogs: correlating {finding['cve_id']} (references only)")
            finding["exploitdb_refs"] = ExploitDBCatalog.search(finding["cve_id"])
            finding["metasploit_modules"] = MetasploitCatalog.search(finding["cve_id"])
        if nvd_error and progress:
            progress(f"NVD unavailable ({nvd_error}); used the bundled vendor catalog")
        return findings[:30]


# ═══════════════════════════════════════════════════════════════
# PASSIVE DISCOVERY SOURCES
# ═══════════════════════════════════════════════════════════════

class FOFAFinder:
    BASE_URL = "https://fofa.info/api/v1/search/all"

    @classmethod
    def search(cls, query: str, page: int = 1, size: int = 100) -> List[Dict[str, Any]]:
        try:
            encoded_query = base64.b64encode(query.encode()).decode()
            url = (
                f"{cls.BASE_URL}?qbase64={encoded_query}"
                f"&page={page}&size={size}"
                f"&fields=ip,port,protocol,server,title,country,city,org,as_number"
            )
            raw = http_get(url, timeout=15)
            data = json.loads(raw)
            results = []
            for item in data.get("results", []):
                results.append({
                    "ip": item[0], "port": item[1], "protocol": item[2],
                    "banner": item[3], "http_title": item[4],
                    "country": item[5], "city": item[6],
                    "org": item[7], "asn": item[8],
                    "discovery_source": "fofa",
                })
            return results
        except Exception as exc:
            logger.warning("FOFA search failed: %s", exc)
            return []

    @classmethod
    def camera_queries(cls) -> List[str]:
        return [
            'port="554"', 'app="Hikvision"', 'app="Dahua"', 'app="Axis"',
            'title="IP Camera"', 'title="webcam"', 'title="Live View"',
            'port="554"&&protocol="rtsp"', 'title="NVR"', 'title="DVR"',
        ]


class ZoomEyeFinder:
    BASE_URL = "https://api.zoomeye.org/host/search"

    @classmethod
    def search(cls, query: str, page: int = 1) -> List[Dict[str, Any]]:
        try:
            url = f"{cls.BASE_URL}?query={urllib.parse.quote(query)}&page={page}&facet=app,os"
            raw = http_get(url, timeout=15)
            data = json.loads(raw)
            results = []
            for match in data.get("matches", []):
                geo = match.get("geoinfo", {})
                results.append({
                    "ip": match.get("ip", ""),
                    "port": match.get("portinfo", 0),
                    "banner": match.get("banner", ""),
                    "country": geo.get("country_names", {}).get("en", ""),
                    "city": geo.get("city_names", {}).get("en", ""),
                    "latitude": geo.get("lat"),
                    "longitude": geo.get("lon"),
                    "org": geo.get("asns", [{}])[0].get("asn", "") if geo.get("asns") else "",
                    "discovery_source": "zoomeye",
                })
            return results
        except Exception as exc:
            logger.warning("ZoomEye search failed: %s", exc)
            return []


class CrtShFinder:
    BASE_URL = "https://crt.sh/"

    @classmethod
    def search(cls, domain: str) -> List[Dict[str, Any]]:
        try:
            url = f"{cls.BASE_URL}?q=%.{domain}&output=json"
            raw = http_get(url, timeout=30)
            data = json.loads(raw)
            camera_keywords = [
                "cam", "camera", "cctv", "nvr", "dvr", "hik", "dahua",
                "axis", "stream", "video", "surveillance", "monitor", "live",
            ]
            results = []
            seen: Set[str] = set()
            for cert in data:
                for name in cert.get("name_value", "").split("\n"):
                    name = name.strip().lower()
                    if name and name not in seen and "*" not in name:
                        if any(kw in name for kw in camera_keywords):
                            seen.add(name)
                            results.append({
                                "domain": name,
                                "issuer": cert.get("issuer_name", ""),
                                "discovery_source": "crtsh",
                            })
            return results
        except Exception as exc:
            logger.warning("crt.sh search failed: %s", exc)
            return []


class DnsEnumerator:
    @classmethod
    def enumerate(cls, domain: str) -> List[Dict[str, Any]]:
        if not HAS_DNS:
            logger.warning("dnspython not installed; skipping DNS enumeration")
            return []
        camera_prefixes = [
            "cam", "camera", "cctv", "nvr", "dvr", "stream", "video",
            "surveillance", "monitor", "live", "cam1", "cam2", "cam01",
            "outdoor", "indoor", "entrance", "lobby", "parking", "gate",
        ]
        results = []
        for prefix in camera_prefixes:
            subdomain = f"{prefix}.{domain}"
            try:
                answers = dns.resolver.resolve(subdomain, "A")
                for rdata in answers:
                    results.append({
                        "domain": subdomain,
                        "ip": str(rdata),
                        "discovery_source": "dns",
                    })
            except Exception as exc:
                logger.debug("DNS lookup failed for %s: %s", subdomain, exc)
        return results


class ShodanFinder:
    """Shodan discovery source (requires free API key)."""
    @classmethod
    def search(cls, query: str, api_key: Optional[str] = None) -> List[Dict[str, Any]]:
        if not HAS_SHODAN or not api_key:
            logger.debug("Shodan unavailable (install: pip install shodan, set API key)")
            return []
        try:
            api = shodan.Shodan(api_key)
            results = []
            for match in api.search(query, limit=100)["matches"]:
                results.append({
                    "ip": match.get("ip_str", ""),
                    "port": match.get("port", 0),
                    "banner": match.get("data", ""),
                    "http_title": match.get("http", {}).get("title", ""),
                    "country": match.get("location", {}).get("country_name", ""),
                    "city": match.get("location", {}).get("city", ""),
                    "latitude": match.get("location", {}).get("latitude"),
                    "longitude": match.get("location", {}).get("longitude"),
                    "org": match.get("org", ""),
                    "asn": match.get("asn", ""),
                    "discovery_source": "shodan",
                })
            return results
        except Exception as exc:
            logger.warning("Shodan search failed: %s", exc)
            return []

    @classmethod
    def camera_queries(cls) -> List[str]:
        return [
            "port:554", "Hikvision", "Dahua", "Axis Communications",
            "webcam", "IP Camera", "NVR", "DVR",
        ]


# ═══════════════════════════════════════════════════════════════
# LOCAL PASSIVE DISCOVERY
# ═══════════════════════════════════════════════════════════════

class ONVIFDiscoverer:
    PROBE_MESSAGE = """<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
 xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"
 xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery"
 xmlns:tns="http://www.onvif.org/ver10/network/wsdl">
<soap:Header>
<wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action>
<wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To>
<wsa:MessageID>urn:uuid:{uuid}</wsa:MessageID>
</soap:Header>
<soap:Body>
<wsd:Probe><wsd:Types>tns:NetworkVideoTransmitter</wsd:Types></wsd:Probe>
</soap:Body>
</soap:Envelope>"""

    @classmethod
    def discover(cls, timeout: float = 5.0) -> List[Dict[str, Any]]:
        results = []
        msg = cls.PROBE_MESSAGE.format(uuid=str(uuid.uuid4()))
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.sendto(msg.encode(), ("239.255.255.250", 3702))
            start = time.time()
            while time.time() - start < timeout:
                try:
                    data, addr = sock.recvfrom(65535)
                    xml_str = data.decode("utf-8", errors="ignore")
                    camera = cls._parse_response(xml_str, addr[0])
                    if camera:
                        camera["discovery_source"] = "onvif"
                        results.append(camera)
                except socket.timeout:
                    break
            sock.close()
        except Exception as exc:
            logger.debug("ONVIF discovery error: %s", exc)
        return results

    @staticmethod
    def _parse_response(xml_str: str, source_ip: str) -> Optional[Dict[str, Any]]:
        try:
            root = ET.fromstring(xml_str)
            result: Dict[str, Any] = {"ip": source_ip, "onvif_data": {"scopes": []}}
            for elem in root.iter():
                if elem.tag.endswith("Scopes") and elem.text:
                    result["onvif_data"]["scopes"] = elem.text.strip().split()
            for elem in root.iter():
                if elem.tag.endswith("XAddrs") and elem.text:
                    result["onvif_url"] = elem.text.strip()
            scope_text = " ".join(result["onvif_data"]["scopes"]).lower()
            for vendor, data in VENDOR_CATALOG.items():
                for known_scope in data.get("onvif_scopes", []):
                    if known_scope.lower() in scope_text:
                        result["vendor"] = vendor
                        return result
                for fp in data.get("fingerprint", []):
                    if fp.lower() in scope_text:
                        result["vendor"] = vendor
                        return result
            return result
        except ET.ParseError:
            return None


class SSDPDiscoverer:
    @classmethod
    def discover(cls, timeout: float = 5.0) -> List[Dict[str, Any]]:
        camera_keywords = [
            "camera", "ipcamera", "videocamera", "mediaserver",
            "digitalsecuritycamera", "hikvision", "dahua", "axis",
            "onvif", "rtsp", "webcam",
        ]
        message = (
            "M-SEARCH * HTTP/1.1\r\n"
            "HOST: 239.255.255.250:1900\r\n"
            "MAN: ssdp:discover\r\n"
            "MX: 2\r\n"
            "ST: ssdp:all\r\n"
            "\r\n"
        )
        results = []
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.sendto(message.encode(), ("239.255.255.250", 1900))
            start = time.time()
            while time.time() - start < timeout:
                try:
                    data, addr = sock.recvfrom(65535)
                    response = data.decode("utf-8", errors="ignore").lower()
                    if any(kw in response for kw in camera_keywords):
                        location = ""
                        for line in response.split("\n"):
                            if line.startswith("location:"):
                                location = line.split(":", 1)[1].strip()
                        results.append({
                            "ip": addr[0],
                            "ssdp_data": {"location": location},
                            "discovery_source": "ssdp",
                        })
                except socket.timeout:
                    break
            sock.close()
        except Exception as exc:
            logger.debug("SSDP discovery error: %s", exc)
        return results


# ═══════════════════════════════════════════════════════════════
# BUILT-IN TCP & SERVICE DISCOVERY
# ═══════════════════════════════════════════════════════════════

class EndpointProfiler:
    """Identify RTSP and web services without attempting authentication."""

    CAMERA_KEYWORDS = (
        "camera", "webcam", "surveillance", "cctv", "dvr", "nvr",
        "network video", "ip camera", "onvif", "hikvision", "dahua",
        "axis", "vivotek", "foscam", "reolink", "uniview",
    )

    @classmethod
    def profile(cls, ip: str, port: int, timeout: float = 1.5) -> Dict[str, Any]:
        rtsp = cls._probe_rtsp(ip, port, timeout)
        if rtsp:
            return rtsp

        schemes = ["https"] if port in TLS_PORTS else ["http", "https"]
        for scheme in schemes:
            web = cls._probe_web(ip, port, scheme, timeout)
            if web:
                return web

        service_type, description = SERVICE_PORTS.get(port, ("tcp", "Open TCP service"))
        return {
            "protocol": "tcp",
            "service_type": service_type,
            "service_name": description,
        }

    @staticmethod
    def _probe_rtsp(ip: str, port: int, timeout: float) -> Dict[str, Any]:
        url_host = f"[{ip}]" if ":" in ip else ip
        request_data = (
            f"OPTIONS rtsp://{url_host}:{port}/ RTSP/1.0\r\n"
            "CSeq: 1\r\n"
            f"User-Agent: {USER_AGENT}\r\n\r\n"
        ).encode("ascii", errors="ignore")
        try:
            with socket.create_connection((ip, port), timeout=timeout) as sock:
                sock.settimeout(timeout)
                sock.sendall(request_data)
                response = sock.recv(4096)
        except (OSError, socket.timeout):
            return {}

        text = response.decode("utf-8", errors="ignore")
        if not text.startswith("RTSP/"):
            return {}
        status_match = re.match(r"RTSP/\d(?:\.\d)?\s+(\d{3})", text)
        status = int(status_match.group(1)) if status_match else 0
        return {
            "protocol": "rtsp",
            "service_type": "rtsp",
            "service_name": "Real-Time Streaming Protocol",
            "banner": text[:1000],
            "rtsp_ok": True,
            "rtsp_status": status,
            "auth_required": status in (401, 403),
            "rtsp_url": f"rtsp://{url_host}:{port}/",
            "camera_signal": True,
        }

    @classmethod
    def _probe_web(cls, ip: str, port: int, scheme: str, timeout: float) -> Dict[str, Any]:
        connection: Any = None
        try:
            if scheme == "https":
                connection = http.client.HTTPSConnection(ip, port, timeout=timeout, context=SSL_CONTEXT)
            else:
                connection = http.client.HTTPConnection(ip, port, timeout=timeout)
            connection.request(
                "GET", "/",
                headers={
                    "User-Agent": USER_AGENT,
                    "Accept": "text/html,application/xhtml+xml,image/*;q=0.8,*/*;q=0.2",
                    "Connection": "close",
                },
            )
            response = connection.getresponse()
            body = response.read(16384)
        except (OSError, http.client.HTTPException, ssl.SSLError):
            return {}
        finally:
            if connection is not None:
                try:
                    connection.close()
                except Exception:
                    pass

        body_text = body.decode("utf-8", errors="ignore")
        title_match = re.search(r"<title[^>]*>(.*?)</title>", body_text, re.IGNORECASE | re.DOTALL)
        title = re.sub(r"\s+", " ", title_match.group(1)).strip()[:200] if title_match else ""
        server = response.getheader("Server", "")
        content_type = response.getheader("Content-Type", "")
        auth_header = response.getheader("WWW-Authenticate", "")
        preview = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", body_text)).strip()[:500]
        combined = f"{server} {title} {content_type} {preview}".lower()
        camera_signal = any(keyword in combined for keyword in cls.CAMERA_KEYWORDS)
        if content_type.lower().startswith(("image/", "video/", "multipart/x-mixed-replace")):
            camera_signal = True
        banner_parts = [f"HTTP {response.status}"]
        if server:
            banner_parts.append(f"Server: {server}")
        if content_type:
            banner_parts.append(f"Content-Type: {content_type}")
        if auth_header:
            banner_parts.append(f"WWW-Authenticate: {auth_header}")
        if preview:
            banner_parts.append(f"Preview: {preview}")
        return {
            "protocol": scheme,
            "service_type": "mjpeg" if "multipart/x-mixed-replace" in content_type.lower() else "http",
            "service_name": "Camera web/stream interface" if camera_signal else "Web interface",
            "banner": "; ".join(banner_parts)[:1500],
            "http_title": title,
            "http_status": response.status,
            "content_type": content_type,
            "auth_required": response.status in (401, 403) or bool(auth_header),
            "camera_signal": camera_signal,
        }


class TCPConnectScanner:
    """Portable, bounded TCP discovery fallback for explicit authorized scope."""

    WORKERS_BY_MODE = {
        ScanMode.STEALTH.value: 16,
        ScanMode.QUIET.value: 32,
        ScanMode.MEDIUM.value: 64,
        ScanMode.AGGRESSIVE.value: 96,
        ScanMode.WAR.value: 128,
        ScanMode.NUKE.value: 160,
    }
    TIMEOUT_BY_MODE = {
        ScanMode.STEALTH.value: 1.2,
        ScanMode.QUIET.value: 0.9,
        ScanMode.MEDIUM.value: 0.65,
        ScanMode.AGGRESSIVE.value: 0.5,
        ScanMode.WAR.value: 0.4,
        ScanMode.NUKE.value: 0.35,
    }

    @classmethod
    def scan(
        cls,
        hosts: List[str],
        ports: List[int],
        mode: str = ScanMode.MEDIUM.value,
        stop_check: Optional[Callable[[], bool]] = None,
    ) -> List[Dict[str, Any]]:
        unique_hosts = sorted(
            set(hosts),
            key=lambda value: (
                ipaddress.ip_address(value).version,
                int(ipaddress.ip_address(value)),
            ),
        )
        if len(unique_hosts) > BUILTIN_SCAN_MAX_HOSTS:
            raise ValueError(
                f"Built-in scanner limit is {BUILTIN_SCAN_MAX_HOSTS} hosts; "
                "use Masscan for a larger authorized scope"
            )
        unique_ports = sorted(set(ports))
        timeout = cls.TIMEOUT_BY_MODE.get(mode, cls.TIMEOUT_BY_MODE[ScanMode.MEDIUM.value])
        workers = cls.WORKERS_BY_MODE.get(mode, cls.WORKERS_BY_MODE[ScanMode.MEDIUM.value])
        results: List[Dict[str, Any]] = []

        def probe(job: Tuple[str, int]) -> Optional[Dict[str, Any]]:
            if stop_check and stop_check():
                return None
            ip, port = job
            try:
                with socket.create_connection((ip, port), timeout=timeout):
                    pass
            except (OSError, socket.timeout):
                return None
            item: Dict[str, Any] = {
                "ip": ip,
                "port": port,
                "discovery_source": "tcp",
            }
            item.update(EndpointProfiler.profile(ip, port, timeout=max(timeout, 1.0)))
            return item

        batch_size = max(1, 2048 // max(1, len(unique_ports)))
        stopped = False
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="oculux-tcp") as executor:
            for offset in range(0, len(unique_hosts), batch_size):
                host_batch = unique_hosts[offset:offset + batch_size]
                jobs = ((ip, port) for ip in host_batch for port in unique_ports)
                for result in executor.map(probe, jobs):
                    if result:
                        results.append(result)
                    if stop_check and stop_check():
                        stopped = True
                        break
                if stopped:
                    break
        return results


# ═══════════════════════════════════════════════════════════════
# MASSCAN
# ═══════════════════════════════════════════════════════════════

class MasscanRunner:
    CAMERA_PORTS = "554,80,8080,8554,443,8443,37777,34567,8000,9000,5000"

    @classmethod
    def scan(
        cls,
        target: str,
        ports: Optional[str] = None,
        rate: int = 5000,
        progress: Optional[Callable[[str], None]] = None,
        stop_check: Optional[Callable[[], bool]] = None,
    ) -> List[Dict[str, Any]]:
        masscan_path = find_tool("masscan")
        if not masscan_path:
            logger.warning("masscan not found in PATH")
            if progress:
                progress("Masscan is not installed")
            return []
        ports = ports or cls.CAMERA_PORTS
        targets = [part.strip() for part in target.split(",") if part.strip()]
        cmd = [masscan_path, *targets, f"-p{ports}", f"--rate={rate}", "--open-only", "-oJ", "-"]
        started = time.monotonic()
        last_update = -5.0
        try:
            with tempfile.TemporaryFile(mode="w+") as stdout_file, tempfile.TemporaryFile(mode="w+") as stderr_file:
                proc = subprocess.Popen(cmd, stdout=stdout_file, stderr=stderr_file, text=True)
                while proc.poll() is None:
                    elapsed = time.monotonic() - started
                    if stop_check and stop_check():
                        if progress:
                            progress("Masscan stop requested; terminating process")
                        proc.terminate()
                        try:
                            proc.wait(timeout=3)
                        except subprocess.TimeoutExpired:
                            proc.kill()
                            proc.wait(timeout=3)
                        return []
                    if elapsed >= 300:
                        proc.terminate()
                        try:
                            proc.wait(timeout=3)
                        except subprocess.TimeoutExpired:
                            proc.kill()
                            proc.wait(timeout=3)
                        if progress:
                            progress("Masscan reached the 300-second safety timeout")
                        return []
                    if progress and elapsed - last_update >= 5:
                        progress(f"Masscan running: {int(elapsed)}s elapsed")
                        last_update = elapsed
                    time.sleep(0.25)

                stdout_file.seek(0)
                stderr_file.seek(0)
                stdout = stdout_file.read()
                stderr = stderr_file.read()
                if proc.returncode:
                    detail = next((line.strip() for line in reversed(stderr.splitlines()) if line.strip()), "unknown error")
                    if progress:
                        progress(f"Masscan exited with code {proc.returncode}: {detail[:240]}")

            entries: List[Dict[str, Any]] = []
            try:
                parsed = json.loads(stdout or "[]")
                entries = parsed if isinstance(parsed, list) else [parsed]
            except json.JSONDecodeError:
                for line in stdout.splitlines():
                    line = line.strip().rstrip(",")
                    if not line or line in ("[", "]"):
                        continue
                    try:
                        entry = json.loads(line)
                        if isinstance(entry, dict):
                            entries.append(entry)
                    except json.JSONDecodeError:
                        continue

            results = []
            for entry in entries:
                ip = entry.get("ip", "")
                for port_info in entry.get("ports", []):
                    results.append({
                        "ip": ip,
                        "port": port_info.get("port", 0),
                        "discovery_source": "masscan",
                    })
            if progress:
                progress(f"Masscan completed in {int(time.monotonic() - started)}s with {len(results)} open ports")
            return results
        except (OSError, subprocess.TimeoutExpired) as exc:
            logger.warning("Masscan failed: %s", exc)
            if progress:
                progress(f"Masscan failed: {exc}")
            return []


# ═══════════════════════════════════════════════════════════════
# NMAP SCANNER
# ═══════════════════════════════════════════════════════════════

class NmapScanner:
    """Nmap integration for deep service/version detection and vuln scripts."""

    @classmethod
    def scan(cls, target: str, ports: Optional[str] = None, mode: str = "medium",
             scripts: bool = False, progress: Optional[Callable[[str], None]] = None) -> List[Dict[str, Any]]:
        nmap_path = find_tool("nmap")
        if not nmap_path:
            logger.warning("nmap not found in PATH")
            if progress:
                progress("Nmap is not installed")
            return []

        mcfg = MODE_CONFIG.get(mode, MODE_CONFIG["medium"])
        flags = mcfg.get("nmap_flags", "-T4 --max-retries 2")
        if scripts:
            flags += " --script default"
        if ports:
            flags += f" -p {ports}"

        cmd = [nmap_path, *flags.split(), "-oX", "-", target]
        if progress:
            progress(f"Nmap: {' '.join(cmd)}")
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            if result.returncode != 0:
                if progress:
                    progress(f"Nmap exited with code {result.returncode}")
                return []
            return cls._parse_xml(result.stdout)
        except (OSError, subprocess.TimeoutExpired) as exc:
            logger.warning("Nmap failed: %s", exc)
            if progress:
                progress(f"Nmap failed: {exc}")
            return []

    @staticmethod
    def _parse_xml(xml_str: str) -> List[Dict[str, Any]]:
        results = []
        try:
            root = ET.fromstring(xml_str)
            for host in root.iter("host"):
                ip = ""
                for addr in host.iter("address"):
                    if addr.get("addrtype") == "ipv4":
                        ip = addr.get("addr", "")
                        break
                if not ip:
                    continue
                for port_elem in host.iter("port"):
                    state = port_elem.find("state")
                    if state is None or state.get("state") != "open":
                        continue
                    port = int(port_elem.get("portid", 0))
                    service = port_elem.find("service")
                    service_name = service.get("name", "") if service is not None else ""
                    product = service.get("product", "") if service is not None else ""
                    version = service.get("version", "") if service is not None else ""
                    banner = f"{product} {version}".strip()
                    results.append({
                        "ip": ip,
                        "port": port,
                        "service_type": service_name,
                        "banner": banner,
                        "discovery_source": "nmap",
                    })
        except ET.ParseError as exc:
            logger.debug("Nmap XML parse error: %s", exc)
        return results


# ═══════════════════════════════════════════════════════════════
# GEO ENRICHER
# ═══════════════════════════════════════════════════════════════

class GeoEnricher:
    """IP geolocation enrichment using free ip-api.com (no API key needed)."""
    BASE_URL = "http://ip-api.com/json/"

    @classmethod
    def enrich(cls, ip: str) -> Dict[str, Any]:
        try:
            url = f"{cls.BASE_URL}{ip}?fields=status,country,city,lat,lon,org,as,isp,regionName,timezone"
            raw = http_get(url, timeout=8, domain="ip-api.com")
            data = json.loads(raw)
            if data.get("status") != "success":
                return {}
            return {
                "country": data.get("country", ""),
                "city": data.get("city", ""),
                "latitude": data.get("lat"),
                "longitude": data.get("lon"),
                "org": data.get("org", ""),
                "asn": data.get("as", ""),
                "region": data.get("regionName", ""),
                "timezone": data.get("timezone", ""),
            }
        except Exception as exc:
            logger.debug("Geo enrichment failed for %s: %s", ip, exc)
            return {}


# ═══════════════════════════════════════════════════════════════
# TELEGRAM NOTIFIER
# ═══════════════════════════════════════════════════════════════

class TelegramNotifier:
    """Send scan results and alerts to a Telegram bot."""
    BASE_URL = "https://api.telegram.org/bot{token}/sendMessage"

    def __init__(self, token: Optional[str] = None, chat_id: Optional[str] = None):
        self.token = token or os.getenv("OCULUX_TG_TOKEN")
        self.chat_id = chat_id or os.getenv("OCULUX_TG_CHAT_ID")

    @property
    def enabled(self) -> bool:
        return bool(self.token and self.chat_id)

    def send(self, message: str) -> bool:
        if not self.enabled:
            return False
        try:
            url = self.BASE_URL.format(token=self.token)
            payload = urllib.parse.urlencode({
                "chat_id": self.chat_id,
                "text": message,
                "parse_mode": "HTML",
            }).encode()
            req = urllib.request.Request(url, data=payload)
            req.add_header("Content-Type", "application/x-www-form-urlencoded")
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status == 200
        except Exception as exc:
            logger.debug("Telegram send failed: %s", exc)
            return False

    def notify_scan_complete(self, stats: Dict[str, Any]) -> None:
        if not self.enabled:
            return
        msg = (
            f"<b>🔍 Oculux Scan Complete</b>\n"
            f"━━━━━━━━━━━━━━━━━\n"
            f"📊 <b>Assets:</b> {stats.get('total_assets', 0)}\n"
            f"🔓 <b>No Password:</b> {stats.get('no_password', 0)}\n"
            f"🔑 <b>Default Creds:</b> {stats.get('default_creds', 0)}\n"
            f"⚠️ <b>Vulnerable:</b> {stats.get('vulnerable', 0)}\n"
            f"🏷️ <b>Vendors:</b> {len(stats.get('by_vendor', {}))}\n"
        )
        self.send(msg)

    def notify_critical_findings(self, findings: List[Dict[str, Any]]) -> None:
        if not self.enabled or not findings:
            return
        critical = [f for f in findings if f.get("severity") == "CRITICAL"][:5]
        if not critical:
            return
        msg = "<b>🚨 Critical CVEs Found</b>\n━━━━━━━━━━━━━━━━━\n"
        for f in critical:
            msg += f"<b>{f.get('cve_id')}</b> — {f.get('title', '')[:60]}\n"
        self.send(msg)


# ═══════════════════════════════════════════════════════════════
# STREAM PROXY (MJPEG)
# ═══════════════════════════════════════════════════════════════

class StreamProxy:
    """Proxy MJPEG streams from cameras to the dashboard for live viewing."""

    @classmethod
    def fetch_mjpeg(cls, url: str, timeout: float = 10.0) -> Optional[bytes]:
        """Fetch a single MJPEG frame from a camera stream URL."""
        try:
            req = urllib.request.Request(url)
            req.add_header("User-Agent", USER_AGENT)
            opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=SSL_CONTEXT))
            with opener.open(req, timeout=timeout) as resp:
                content_type = resp.headers.get("Content-Type", "")
                if "multipart/x-mixed-replace" in content_type:
                    # Read first JPEG frame from multipart stream
                    boundary = None
                    for part in content_type.split(";"):
                        part = part.strip()
                        if part.startswith("boundary="):
                            boundary = part.split("=", 1)[1].strip('"')
                            break
                    if not boundary:
                        return None
                    data = b""
                    while True:
                        chunk = resp.read(4096)
                        if not chunk:
                            break
                        data += chunk
                        if b"--" + boundary.encode() in data and b"\xff\xd8" in data:
                            # Found start of JPEG frame
                            jpeg_start = data.find(b"\xff\xd8")
                            if jpeg_start >= 0:
                                return data[jpeg_start:]
                        if len(data) > 2 * 1024 * 1024:
                            break
                else:
                    return resp.read()
        except Exception as exc:
            logger.debug("MJPEG fetch failed for %s: %s", url, exc)
        return None

    @classmethod
    def build_rtsp_url(cls, ip: str, port: int, vendor: str = "Unknown", user: str = "", passwd: str = "") -> str:
        """Build an RTSP URL for a camera based on vendor."""
        auth = f"{user}:{passwd}@" if user else ""
        host = f"[{ip}]" if ":" in ip else ip
        paths = VENDOR_CATALOG.get(vendor, {}).get("rtsp_paths", ["/live"])
        path = paths[0].replace("{ch}", "1") if paths else "/live"
        return f"rtsp://{auth}{host}:{port}{path}"


# ═══════════════════════════════════════════════════════════════
# HTML REPORT GENERATOR
# ═══════════════════════════════════════════════════════════════

class HTMLReportGenerator:
    """Generate a standalone HTML report with embedded CSS/JS."""

    @classmethod
    def generate(cls, assets: List[Dict[str, Any]], stats: Dict[str, Any],
                 findings: Optional[Dict[int, List[Dict[str, Any]]]] = None,
                 title: str = "Oculux Camera Verification Report") -> str:
        findings = findings or {}
        rows = ""
        for a in assets:
            conf = a.get("confidence", 0) or 0
            conf_color = "#22c55e" if conf >= 80 else "#eab308" if conf >= 60 else "#ef4444"
            al = a.get("access_level", "unknown")
            al_badge = {
                "full": ("🔓 No Password", "#22c55e"),
                "default": ("🔑 Default", "#eab308"),
                "needs_cracking": ("🔒 Needs Crack", "#a855f7"),
                "cracked": ("🔓 Cracked", "#22c55e"),
            }.get(al, ("?", "#0ea5e9"))
            asset_findings = findings.get(a.get("id"), [])
            cve_badges = ""
            for f in asset_findings[:3]:
                sev = str(f.get("severity", "")).upper()
                sev_color = "#ef4444" if sev == "CRITICAL" else "#eab308" if sev == "HIGH" else "#0ea5e9"
                cve_badges += f'<span class="cve-badge" style="background:{sev_color}22;color:{sev_color};border-color:{sev_color}">{f.get("cve_id", "")}</span>'
            rows += f"""
            <tr>
                <td>{a.get("primary_ip", "")}</td>
                <td>{a.get("primary_port", "") or "-"}</td>
                <td>{a.get("vendor", "?")}</td>
                <td>{a.get("model", "-")}</td>
                <td><div class="conf-bar"><div style="width:{conf}%;background:{conf_color}"></div></div><span style="font-size:.7rem;color:{conf_color}">{conf}%</span></td>
                <td><span class="badge" style="background:{al_badge[1]}22;color:{al_badge[1]};border-color:{al_badge[1]}">{al_badge[0]}</span></td>
                <td>{cve_badges or '<span style="color:#8899ad;font-size:.7rem">None</span>'}</td>
                <td>{a.get("country", "-")}</td>
                <td>{a.get("discovery_source", "-")}</td>
            </tr>"""
        by_vendor = stats.get("by_vendor", {})
        vendor_rows = "".join(
            f'<div class="vendor-bar"><span>{v}</span><div class="bar"><div style="width:{min(100, c / max(1, max(by_vendor.values())) * 100)}%"></div></div><span>{c}</span></div>'
            for v, c in sorted(by_vendor.items(), key=lambda x: -x[1])[:10]
        )
        return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>{title}</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;700&family=Inter:wght@300;400;600&display=swap');
:root{{--bg:#080c14;--bg2:#0f1623;--bg3:#182234;--brd:#243044;--tx:#e2e8f0;--tx2:#8899ad;--acc:#0ea5e9}}
*{{margin:0;padding:0;box-sizing:border-box}}body{{font-family:'Inter',sans-serif;background:var(--bg);color:var(--tx);padding:2rem}}
.hdr{{display:flex;justify-content:space-between;align-items:center;margin-bottom:2rem;padding-bottom:1rem;border-bottom:1px solid var(--brd)}}
h1{{font-family:'JetBrains Mono',monospace;font-size:1.3rem;color:var(--acc)}}h1 span{{color:var(--tx2);font-weight:300;font-size:.7rem}}
.meta{{color:var(--tx2);font-size:.7rem;font-family:'JetBrains Mono',monospace}}
.stats{{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:.7rem;margin-bottom:2rem}}
.stat{{background:var(--bg3);border:1px solid var(--brd);border-radius:8px;padding:.8rem}}
.stat .l{{font-size:.55rem;color:var(--tx2);text-transform:uppercase;letter-spacing:1px}}
.stat .v{{font-family:'JetBrains Mono',monospace;font-size:1.2rem;font-weight:700;margin-top:.2rem}}
h2{{font-size:.85rem;color:var(--tx2);margin:1.5rem 0 .7rem;text-transform:uppercase;letter-spacing:1px}}
table{{width:100%;border-collapse:collapse;background:var(--bg3);border:1px solid var(--brd);border-radius:8px;overflow:hidden}}
th{{padding:.5rem .6rem;text-align:left;font-size:.55rem;color:var(--tx2);text-transform:uppercase;letter-spacing:1px;background:rgba(0,0,0,.3);border-bottom:1px solid var(--brd)}}
td{{padding:.5rem .6rem;font-size:.7rem;font-family:'JetBrains Mono',monospace;border-bottom:1px solid rgba(36,48,68,.4)}}
tr:hover{{background:rgba(14,165,233,.04)}}
.badge{{padding:.1rem .3rem;border-radius:3px;font-size:.55rem;font-weight:600;border:1px solid}}
.cve-badge{{padding:.1rem .3rem;border-radius:3px;font-size:.55rem;font-weight:600;border:1px solid;margin-right:.2rem}}
.conf-bar{{width:60px;height:4px;background:var(--bg);border-radius:2px;overflow:hidden;display:inline-block;vertical-align:middle;margin-right:.3rem}}
.conf-bar div{{height:100%;border-radius:2px}}
.vendor-bar{{display:flex;align-items:center;gap:.5rem;margin-bottom:.4rem;font-size:.7rem;font-family:'JetBrains Mono',monospace}}
.vendor-bar .bar{{flex:1;height:6px;background:var(--bg);border-radius:3px;overflow:hidden}}
.vendor-bar .bar div{{height:100%;background:var(--acc);border-radius:3px}}
.footer{{margin-top:2rem;padding-top:1rem;border-top:1px solid var(--brd);color:var(--tx2);font-size:.65rem;font-family:'JetBrains Mono',monospace}}
</style></head><body>
<div class="hdr"><h1>OCULUX <span>// {title}</span></h1><div class="meta">Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</div></div>
<div class="stats">
<div class="stat"><div class="l">Total Assets</div><div class="v" style="color:var(--acc)">{stats.get("total_assets", 0)}</div></div>
<div class="stat"><div class="l">No Password</div><div class="v" style="color:#22c55e">{stats.get("no_password", 0)}</div></div>
<div class="stat"><div class="l">Default Creds</div><div class="v" style="color:#eab308">{stats.get("default_creds", 0)}</div></div>
<div class="stat"><div class="l">Vulnerable</div><div class="v" style="color:#ef4444">{stats.get("vulnerable", 0)}</div></div>
<div class="stat"><div class="l">Vendors</div><div class="v" style="color:#a855f7">{stats.get("unique_vendors", 0)}</div></div>
<div class="stat"><div class="l">CVEs Tracked</div><div class="v" style="color:#06b6d4">{stats.get("total_cves", 0)}</div></div>
</div>
<h2>Vendor Distribution</h2>
<div style="background:var(--bg3);border:1px solid var(--brd);border-radius:8px;padding:1rem">{vendor_rows or '<div style="color:var(--tx2);font-size:.7rem">No data</div>'}</div>
<h2>Assets ({len(assets)})</h2>
<table><thead><tr><th>IP</th><th>Port</th><th>Vendor</th><th>Model</th><th>Confidence</th><th>Access</th><th>CVEs</th><th>Country</th><th>Source</th></tr></thead>
<tbody>{rows or '<tr><td colspan="9" style="text-align:center;color:var(--tx2)">No assets found</td></tr>'}</tbody></table>
<div class="footer">Generated by Oculux v7.5 — Defensive Camera Verification Framework</div>
</body></html>"""


# ═══════════════════════════════════════════════════════════════
# CREDENTIAL CHECKER
# ═══════════════════════════════════════════════════════════════

class CredentialChecker:
    @classmethod
    def check_http(cls, ip: str, port: int, vendor: str = "Unknown", scheme: str = "http") -> Dict[str, Any]:
        result = {
            "no_password": False, "default_cred": False,
            "auth_user": None, "auth_pass": None, "paths_found": [],
        }
        scheme = "https" if scheme == "https" else "http"
        creds = list(VENDOR_CATALOG.get(vendor, {}).get("default_creds", []))
        creds += [("admin", "admin"), ("admin", ""), ("", "")]
        paths = VENDOR_CATALOG.get(vendor, {}).get("http_paths", ["/"])

        for path in paths:
            url = f"{scheme}://{ip}:{port}{path}"
            try:
                req = urllib.request.Request(url)
                req.add_header("User-Agent", USER_AGENT)
                if scheme == "https":
                    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=SSL_CONTEXT))
                else:
                    opener = urllib.request.build_opener()
                try:
                    resp = opener.open(req, timeout=5)
                    if resp.getcode() == 200:
                        result["no_password"] = True
                        result["paths_found"].append(path)
                        result["auth_user"] = ""
                        result["auth_pass"] = ""
                        return result
                except urllib.error.HTTPError as e:
                    if e.code not in (401, 403):
                        continue
                except Exception as exc:
                    logger.debug("HTTP check error for %s: %s", url, exc)
                    continue

                for user, passwd in creds:
                    try:
                        req2 = urllib.request.Request(url)
                        req2.add_header("User-Agent", USER_AGENT)
                        if user:
                            cred = base64.b64encode(f"{user}:{passwd}".encode()).decode()
                            req2.add_header("Authorization", f"Basic {cred}")
                        resp = opener.open(req2, timeout=5)
                        if resp.getcode() == 200:
                            result["default_cred"] = True
                            result["auth_user"] = user
                            result["auth_pass"] = passwd
                            result["paths_found"].append(path)
                            return result
                    except urllib.error.HTTPError:
                        continue
                    except Exception as exc:
                        logger.debug("HTTP auth check error for %s: %s", url, exc)
                        continue
            except Exception as exc:
                logger.debug("HTTP request error for %s: %s", url, exc)
                continue
        return result

    @classmethod
    def check_rtsp(cls, ip: str, port: int = 554, vendor: str = "Unknown") -> Dict[str, Any]:
        result = {
            "no_password": False, "default_cred": False,
            "auth_user": None, "auth_pass": None, "rtsp_ok": False,
        }
        creds = list(VENDOR_CATALOG.get(vendor, {}).get("default_creds", []))
        creds += [("", ""), ("admin", "admin")]
        rtsp_paths = VENDOR_CATALOG.get(vendor, {}).get("rtsp_paths", ["/"])

        for user, passwd in creds:
            for path_tmpl in rtsp_paths[:3]:
                path = path_tmpl.replace("{ch}", "1")
                sock = None
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(5)
                    sock.connect((ip, port))
                    rtsp_req = (
                        f"DESCRIBE rtsp://{ip}:{port}{path} RTSP/1.0\r\n"
                        f"CSeq: 1\r\n"
                        f"User-Agent: {USER_AGENT}\r\n"
                    )
                    if user:
                        cred = base64.b64encode(f"{user}:{passwd}".encode()).decode()
                        rtsp_req += f"Authorization: Basic {cred}\r\n"
                    rtsp_req += "\r\n"
                    sock.send(rtsp_req.encode())
                    response = sock.recv(4096)
                    if b"200 OK" in response:
                        if not user:
                            result["no_password"] = True
                        else:
                            result["default_cred"] = True
                        result["auth_user"] = user or ""
                        result["auth_pass"] = passwd or ""
                        result["rtsp_ok"] = True
                        return result
                    elif b"401" in response:
                        continue
                    else:
                        break
                except Exception as exc:
                    logger.debug("RTSP check error for %s:%d: %s", ip, port, exc)
                    continue
                finally:
                    if sock:
                        try:
                            sock.close()
                        except Exception:
                            pass
        return result


class DefaultCredentialAuditor:
    """Single-asset default credential checks for authorized defensive audits."""
    HTTP_PORTS = {80, 81, 82, 83, 84, 85, 88, 443, 8000, 8001, 8080, 8081, 8088, 8443, 8888, 9000}
    RTSP_PORTS = {554, 8554}

    @classmethod
    def _candidates(cls, asset: Dict[str, Any], services: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        ip = asset.get("primary_ip")
        candidates: List[Dict[str, Any]] = []
        seen: Set[Tuple[str, int, str]] = set()

        def add(port_value: Any, protocol: str = "") -> None:
            try:
                port = int(port_value)
            except (TypeError, ValueError):
                return
            if not ip or not 1 <= port <= 65535:
                return
            proto = (protocol or "").lower()
            if not proto:
                proto = "rtsp" if port in cls.RTSP_PORTS else "https" if port in (443, 8443) else "http" if port in cls.HTTP_PORTS else "tcp"
            if proto not in {"http", "https", "rtsp"} and port not in cls.HTTP_PORTS | cls.RTSP_PORTS:
                return
            key = (ip, port, proto)
            if key not in seen:
                seen.add(key)
                candidates.append({"ip": ip, "port": port, "protocol": proto})

        add(asset.get("primary_port"), "")
        for service in services:
            proto = str(service.get("service_type") or service.get("protocol") or "")
            if "rtsp" in proto.lower():
                add(service.get("port"), "rtsp")
            elif "http" in proto.lower():
                add(service.get("port"), "http")
            else:
                add(service.get("port"), "")
        return candidates

    @classmethod
    def audit(
        cls,
        asset: Dict[str, Any],
        services: List[Dict[str, Any]],
        progress: Optional[Callable[[str], None]] = None,
    ) -> Dict[str, Any]:
        vendor = str(asset.get("vendor") or "Unknown")
        candidates = cls._candidates(asset, services)
        if not candidates:
            return {"status": "no_supported_service", "message": "No HTTP or RTSP service was available to test"}

        attempts = 0
        for candidate in candidates[:8]:
            attempts += 1
            ip = candidate["ip"]
            port = candidate["port"]
            protocol = candidate["protocol"]
            if progress:
                progress(f"Testing {protocol.upper()} defaults on {ip}:{port}")
            if protocol == "rtsp":
                result = CredentialChecker.check_rtsp(ip, port, vendor)
            else:
                result = CredentialChecker.check_http(ip, port, vendor, scheme=protocol)

            base = {"port": port, "protocol": protocol, "attempts": attempts}
            if result.get("no_password"):
                return {
                    **base,
                    "status": "no_password_found",
                    "access_level": "full",
                    "has_password": 0,
                    "auth_user": "",
                    "auth_pass": "",
                    "message": "The service allowed access without authentication",
                }
            if result.get("default_cred"):
                return {
                    **base,
                    "status": "default_credentials_found",
                    "access_level": "default",
                    "has_password": 1,
                    "auth_user": result.get("auth_user", ""),
                    "auth_pass": result.get("auth_pass", ""),
                    "message": "A known vendor/default credential was accepted",
                }

        return {
            "status": "no_default_credentials_found",
            "access_level": "needs_cracking",
            "has_password": 1,
            "attempts": attempts,
            "message": "No no-password access or known vendor default credential was accepted",
        }

    @staticmethod
    def sanitized(result: Dict[str, Any]) -> Dict[str, Any]:
        safe = dict(result)
        safe.pop("auth_pass", None)
        if "auth_user" in safe:
            safe["username"] = safe.pop("auth_user")
        safe["password_value_returned"] = False
        return safe


# ═══════════════════════════════════════════════════════════════
# HYDRA CRACKER
# ═══════════════════════════════════════════════════════════════

class HydraCracker:
    @classmethod
    def crack(cls, ip: str, port: int, protocol: str = "http", paths: Optional[List[str]] = None,
              users: Optional[List[str]] = None, passwords: Optional[List[str]] = None, threads: int = 4) -> Dict[str, Any]:
        hydra_path = find_tool("hydra")
        if not hydra_path:
            return {"status": "error", "message": "Hydra not installed. Install: sudo apt install hydra"}

        users = users or ["admin", "root", "guest", "user", "operator", "viewer"]
        passwords = passwords or COMMON_PASSWORDS

        user_file = pass_file = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as uf:
                uf.write("\n".join(users))
                user_file = uf.name

            with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as pf:
                pf.write("\n".join(passwords))
                pass_file = pf.name

            path = paths[0] if paths else "/"
            cmd = [
                hydra_path, "-L", user_file, "-P", pass_file,
                "-t", str(threads), "-f", "-q", ip,
                "http-get" if protocol == "http" else protocol,
            ]
            if protocol == "http":
                cmd.append(path)

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

            for line in result.stdout.split("\n"):
                if "login:" in line.lower() and "password:" in line.lower():
                    match = re.search(r"login:\s*(\S+)\s+password:\s*(\S+)", line)
                    if match:
                        return {"status": "cracked", "user": match.group(1), "password": match.group(2)}

            return {"status": "failed", "message": "No valid credentials found"}

        except subprocess.TimeoutExpired:
            return {"status": "timeout", "message": "Hydra timed out (300s limit)"}
        except Exception as exc:
            return {"status": "error", "message": str(exc)}
        finally:
            for f in (user_file, pass_file):
                if f:
                    try:
                        os.unlink(f)
                    except OSError:
                        pass


# ═══════════════════════════════════════════════════════════════
# METASPLOIT RUNNER
# ═══════════════════════════════════════════════════════════════

class MetasploitRunner:
    @classmethod
    def run_exploit(cls, module: str, rhost: str, rport: int = 80, payload: Optional[str] = None,
                    options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        msfconsole_path = find_tool("msfconsole")
        if not msfconsole_path:
            return {"status": "error", "message": "Metasploit not installed. Install: sudo apt install metasploit-framework"}

        commands = [f"use {module}", f"set RHOSTS {rhost}", f"set RPORT {rport}"]
        if payload:
            commands.append(f"set PAYLOAD {payload}")
        if options:
            for key, val in options.items():
                commands.append(f"set {key} {val}")
        commands.extend(["run", "exit"])

        rc_content = "\n".join(commands)
        with tempfile.NamedTemporaryFile(mode="w", suffix=".rc", delete=False) as f:
            f.write(rc_content)
            rc_file = f.name

        try:
            cmd = [msfconsole_path, "-q", "-r", rc_file]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            os.unlink(rc_file)
            return {
                "status": "completed",
                "output": result.stdout[-3000:] if len(result.stdout) > 3000 else result.stdout,
                "module": module,
            }
        except subprocess.TimeoutExpired:
            os.unlink(rc_file)
            return {"status": "timeout", "message": "Metasploit timed out (180s limit)"}
        except Exception as exc:
            os.unlink(rc_file)
            return {"status": "error", "message": str(exc)}


# ═══════════════════════════════════════════════════════════════
# THUMBNAIL CAPTURE
# ═══════════════════════════════════════════════════════════════

class ThumbnailCapture:
    @classmethod
    def grab(cls, url: str, output_dir: str = "thumbnails", timeout: int = 10) -> Optional[str]:
        ffmpeg_path = find_tool("ffmpeg")
        if not ffmpeg_path:
            return None
        os.makedirs(output_dir, exist_ok=True)
        fname = f"{hashlib.md5(url.encode()).hexdigest()[:12]}.jpg"
        fpath = os.path.join(output_dir, fname)
        try:
            cmd = [
                ffmpeg_path, "-y", "-rtsp_transport", "tcp", "-i", url,
                "-frames:v", "1", "-q:v", "2", "-timeout", str(timeout * 1000000), fpath,
            ]
            subprocess.run(cmd, capture_output=True, timeout=timeout + 5)
            if os.path.exists(fpath) and os.path.getsize(fpath) > 0:
                return fpath
        except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
            logger.debug("ffmpeg RTSP capture failed: %s", exc)
        return None

    @classmethod
    def grab_http(cls, ip: str, port: int, path: str, output_dir: str = "thumbnails", timeout: int = 10) -> Optional[str]:
        os.makedirs(output_dir, exist_ok=True)
        fname = f"{hashlib.md5(f'{ip}:{port}{path}'.encode()).hexdigest()[:12]}.jpg"
        fpath = os.path.join(output_dir, fname)
        try:
            url = f"http://{ip}:{port}{path}"
            req = urllib.request.Request(url)
            req.add_header("User-Agent", USER_AGENT)
            opener = urllib.request.build_opener()
            with opener.open(req, timeout=timeout) as resp:
                if resp.getcode() == 200:
                    data = resp.read()
                    if len(data) > 100:
                        with open(fpath, "wb") as f:
                            f.write(data)
                        return fpath
        except Exception as exc:
            logger.debug("HTTP snapshot failed for %s: %s", url, exc)
        return None


# ═══════════════════════════════════════════════════════════════
# TASK QUEUE
# ═══════════════════════════════════════════════════════════════

class TaskQueue:
    def __init__(self, max_workers: int = 8, max_retries: int = 3):
        self.queue: queue.PriorityQueue = queue.PriorityQueue()
        self.max_workers = max_workers
        self.max_retries = max_retries
        self.running = False
        self.workers: List[threading.Thread] = []
        self.total = 0
        self.completed = 0
        self.failed = 0
        self._lock = threading.Lock()

    def add_task(self, func: Callable[..., Any], args: Optional[Dict[str, Any]] = None, priority: int = 5) -> None:
        with self._lock:
            self.total += 1
            task_id = self.total
        self.queue.put((priority, task_id, func, args or {}))

    def start(self) -> None:
        self.running = True
        for _ in range(self.max_workers):
            worker = threading.Thread(target=self._worker, daemon=True)
            worker.start()
            self.workers.append(worker)

    def stop(self) -> None:
        self.running = False

    def _worker(self) -> None:
        while self.running:
            try:
                priority, task_id, func, args = self.queue.get(timeout=1)
            except queue.Empty:
                continue
            retries = 0
            while retries < self.max_retries:
                try:
                    func(**args)
                    with self._lock:
                        self.completed += 1
                    break
                except Exception as exc:
                    retries += 1
                    logger.debug("Task failed (attempt %d/%d): %s", retries, self.max_retries, exc)
                    if retries < self.max_retries:
                        delay = 2.0 ** retries + random.uniform(0, 1)
                        time.sleep(delay)
                    else:
                        with self._lock:
                            self.failed += 1
            self.queue.task_done()

    def get_status(self) -> Dict[str, Any]:
        return {
            "total": self.total,
            "completed": self.completed,
            "failed": self.failed,
            "pending": self.queue.qsize(),
            "workers": len(self.workers),
        }


# ═══════════════════════════════════════════════════════════════
# ORCHESTRATOR
# ═══════════════════════════════════════════════════════════════

class DiscoveryOrchestrator:
    PHASE_DISCOVER = "discover"
    PHASE_IDENTIFY = "identify"
    PHASE_VERIFY = "verify"

    def __init__(self, db: Database, scope_mgr: ScopeManager, proxy_mgr: ProxyManager,
                 targets: Optional[List[str]] = None, sources: Optional[List[str]] = None,
                 mode: str = "medium", check_creds: bool = True, grab_thumbs: bool = True,
                 custom_ports: Optional[Set[int]] = None):
        self.db = db
        self.scope_mgr = scope_mgr
        self.proxy_mgr = proxy_mgr
        self.targets = targets or []
        self.sources = sources or ["fofa", "zoomeye", "crtsh", "dns", "masscan", "tcp", "onvif", "ssdp"]
        self.mode = mode
        self.mcfg = MODE_CONFIG.get(mode, MODE_CONFIG["medium"])
        self.check_creds = check_creds
        self.grab_thumbs = grab_thumbs
        self.custom_ports = custom_ports or set()
        self.results: List[Dict[str, Any]] = []
        self.running = False
        self.progress: List[str] = []
        self.phase: Optional[str] = None
        self.stats = {
            "discovered": 0, "identified": 0, "verified": 0,
            "vulnerable": 0, "no_password": 0,
        }

    def log(self, message: str, level: str = "info") -> None:
        timestamp = datetime.now().strftime("%H:%M:%S")
        prefix = {"info": "●", "ok": "✓", "err": "✗", "warn": "⚠"}.get(level, "●")
        self.progress.append(f"[{timestamp}] {prefix} {message}")
        logger.info("[%s] %s", level.upper(), message)

    def run(self, phases: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        if phases is None:
            phases = [self.PHASE_DISCOVER, self.PHASE_IDENTIFY, self.PHASE_VERIFY]
        self.running = True

        if self.PHASE_DISCOVER in phases and self.running:
            self.phase = self.PHASE_DISCOVER
            self.log(f"Phase 1: Discovery (mode: {self.mode})")
            discovered = self._phase_discover()
            self.stats["discovered"] = len(discovered)
            self.log(f"Discovery found {len(discovered)} endpoints", "ok")

        if self.PHASE_IDENTIFY in phases and self.running:
            self.phase = self.PHASE_IDENTIFY
            self.log("Phase 2: Identification & Confidence Scoring")
            self._phase_identify()
            self.log(f"Identified {self.stats['identified']} cameras", "ok")

        if self.PHASE_VERIFY in phases and self.running and self.check_creds:
            self.phase = self.PHASE_VERIFY
            self.log("Phase 3: Verification")
            self._phase_verify()
            self.log(f"Verified {self.stats['verified']}, {self.stats['vulnerable']} vulnerable", "ok")

        self.running = False
        self.phase = None
        self.log("Pipeline complete", "ok")
        return self.results

    def _phase_discover(self) -> List[Dict[str, Any]]:
        all_discovered: List[Dict[str, Any]] = []

        if "fofa" in self.sources:
            self.log("FOFA: Searching free tier...")
            for query in FOFAFinder.camera_queries()[:5]:
                results = FOFAFinder.search(query, size=50)
                all_discovered.extend(results)
                self.log(f"  FOFA '{query[:30]}': {len(results)} results")
                time.sleep(2)

        if "zoomeye" in self.sources:
            self.log("ZoomEye: Searching free tier...")
            for query in ["port:554", "app:Hikvision", "app:Dahua", "app:Axis"]:
                results = ZoomEyeFinder.search(query)
                all_discovered.extend(results)
                self.log(f"  ZoomEye '{query}': {len(results)} results")
                time.sleep(2)

        if "shodan" in self.sources:
            self.log("Shodan: Searching...")
            for query in ShodanFinder.camera_queries()[:3]:
                results = ShodanFinder.search(query)
                all_discovered.extend(results)
                self.log(f"  Shodan '{query}': {len(results)} results")
                time.sleep(2)

        if "crtsh" in self.sources and self.scope_mgr.domains:
            self.log("crt.sh: Certificate Transparency search...")
            for domain in self.scope_mgr.domains:
                results = CrtShFinder.search(domain)
                all_discovered.extend(results)
                self.log(f"  crt.sh '{domain}': {len(results)} camera domains")
                time.sleep(1)

        if "dns" in self.sources and self.scope_mgr.domains:
            self.log("DNS: Enumerating subdomains...")
            for domain in self.scope_mgr.domains:
                results = DnsEnumerator.enumerate(domain)
                all_discovered.extend(results)
                self.log(f"  DNS '{domain}': {len(results)} results")

        if "onvif" in self.sources:
            self.log("ONVIF: WS-Discovery broadcast...")
            results = ONVIFDiscoverer.discover()
            all_discovered.extend(results)
            self.log(f"  ONVIF: {len(results)} cameras found")

        if "ssdp" in self.sources:
            self.log("SSDP: UPnP broadcast sweep...")
            results = SSDPDiscoverer.discover()
            all_discovered.extend(results)
            self.log(f"  SSDP: {len(results)} devices found")

        active_results: List[Dict[str, Any]] = []
        scan_targets = list(dict.fromkeys(self.targets or self.scope_mgr.cidrs))
        scan_ports = ports_for_mode(self.mode, self.custom_ports)

        if "masscan" in self.sources and scan_targets:
            target_str = ",".join(scan_targets)
            if self.mcfg["masscan"] and find_tool("masscan"):
                self.log(f"Masscan: Fast sweep on {target_str} (rate={self.mcfg['masscan_rate']})...")
                mode_ports = CAMERA_PORTS_BY_MODE.get(self.mode, CAMERA_PORTS_BY_MODE["medium"])
                if self.custom_ports and isinstance(mode_ports, str):
                    ports_str = mode_ports
                else:
                    ports_str = ",".join(str(p) for p in scan_ports)
                results = MasscanRunner.scan(
                    target_str,
                    ports=ports_str,
                    rate=self.mcfg["masscan_rate"],
                    progress=lambda message: self.log(f"  {message}"),
                    stop_check=lambda: not self.running,
                )
                active_results.extend(results)
                self.log(f"  Masscan: {len(results)} open ports found", "ok")

        should_run_tcp = "tcp" in self.sources and not active_results
        if should_run_tcp and self.scope_mgr.has_scope():
            hosts = sorted(self.scope_mgr.resolve())
            self.log(f"TCP: Scanning {len(hosts)} scoped hosts across {len(scan_ports)} camera ports...")
            try:
                results = TCPConnectScanner.scan(
                    hosts,
                    scan_ports,
                    mode=self.mode,
                    stop_check=lambda: not self.running,
                )
                active_results.extend(results)
                self.log(f"  TCP: {len(results)} open services found", "ok")
            except ValueError as exc:
                self.log(f"  TCP: {exc}", "warn")

        if active_results:
            if any(item.get("discovery_source") == "masscan" for item in active_results):
                self.log("Profiling open services and detecting RTSP on non-standard ports...")
                active_results = self._profile_results(active_results)
            all_discovered.extend(active_results)

        seen: Set[Tuple[str, int]] = set()
        unique: List[Dict[str, Any]] = []
        for item in all_discovered:
            key = (item.get("ip", ""), item.get("port", 0))
            if key not in seen and key[0]:
                seen.add(key)
                unique.append(item)

        self.results = unique
        return unique

    def _profile_results(self, items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        def profile(item: Dict[str, Any]) -> Dict[str, Any]:
            if not self.running:
                return item
            details = EndpointProfiler.profile(item["ip"], int(item.get("port", 0)))
            merged = dict(item)
            merged.update(details)
            return merged

        with ThreadPoolExecutor(max_workers=32, thread_name_prefix="oculux-profile") as executor:
            return list(executor.map(profile, items))

    def _phase_identify(self) -> None:
        for item in self.results:
            if not self.running:
                break
            ip = item.get("ip", "")
            port = item.get("port", 0)
            if self.db.is_blocked(ip):
                self.log(f"  Skipping {ip} (blocklisted)", "warn")
                continue
            if self.scope_mgr.has_scope() and not self.scope_mgr.in_scope(ip):
                continue

            vendor = self._match_vendor(item)
            item["vendor"] = vendor
            item["model"] = self._extract_model(item)
            item["firmware"] = self._extract_firmware(item)
            item["camera_type"] = self._classify_camera(item)
            item["oui"] = self._extract_oui(item)

            score, reasons, classification = ConfidenceScorer.score(item)
            item["confidence"] = score
            item["confidence_reasons"] = reasons
            item["classification"] = classification

            cves, cve_conf = CVEMatcher.match(vendor, item.get("model"), item.get("firmware"))
            item["cves"] = cves
            item["cve_confidence"] = cve_conf
            self.stats["identified"] += 1

            asset_data = {k: item[k] for k in [
                "ip", "port", "vendor", "model", "firmware", "camera_type",
                "confidence", "confidence_reasons", "classification",
                "access_level", "has_password", "status", "country", "city",
                "latitude", "longitude", "org", "asn", "oui",
                "discovery_source", "tags",
            ] if k in item}
            asset_id = self.db.upsert_asset(asset_data, self.scope_mgr)
            if asset_id:
                service_data = {k: item[k] for k in [
                    "ip", "port", "protocol", "banner", "http_title",
                    "paths", "cves", "cve_confidence", "onvif_data", "rtsp_url",
                ] if k in item}
                service_data["service_type"] = item.get(
                    "service_type", "rtsp" if port in (554, 8554) else "tcp"
                )
                if not service_data.get("banner") and item.get("service_name"):
                    service_data["banner"] = item["service_name"]
                self.db.upsert_service(asset_id, service_data)
                item["asset_id"] = asset_id

    def _phase_verify(self) -> None:
        max_creds = self.mcfg["max_creds"]
        count = 0
        for item in self.results:
            if not self.running or count >= max_creds:
                break
            ip = item.get("ip", "")
            port = item.get("port", 0)
            vendor = item.get("vendor", "Unknown")
            if item.get("confidence", 0) < 20:
                continue
            if item.get("access_level") in ("full", "default"):
                continue
            self.log(f"  Checking {ip}:{port}")

            if port in (554, 8554):
                cred_result = CredentialChecker.check_rtsp(ip, port, vendor)
                if cred_result.get("rtsp_ok"):
                    item["rtsp_ok"] = True
                    item["rtsp_paths"] = ["/"]
            else:
                cred_result = CredentialChecker.check_http(ip, port, vendor)

            if cred_result.get("no_password"):
                item["access_level"] = "full"
                item["has_password"] = 0
                item["status"] = "vulnerable"
                item["auth_user"] = ""
                item["auth_pass"] = ""
                self.stats["vulnerable"] += 1
                self.stats["no_password"] += 1
                self.log(f"  ✓ NO PASSWORD: {ip}:{port}", "ok")
            elif cred_result.get("default_cred"):
                item["access_level"] = "default"
                item["has_password"] = 1
                item["status"] = "vulnerable"
                item["auth_user"] = cred_result.get("auth_user", "")
                item["auth_pass"] = cred_result.get("auth_pass", "")
                self.stats["vulnerable"] += 1
                self.log(f"  ✓ DEFAULT CREDS: {ip}:{port}", "ok")
            else:
                item["access_level"] = "needs_cracking"
                item["has_password"] = 1

            self.stats["verified"] += 1
            count += 1

            if self.grab_thumbs and item.get("access_level") in ("full", "default"):
                thumb_path = None
                if port in (554, 8554) and item.get("rtsp_ok"):
                    rtsp_url = f"rtsp://{ip}:{port}/live"
                    thumb_path = ThumbnailCapture.grab(rtsp_url)
                elif vendor in VENDOR_CATALOG:
                    for snap_path in VENDOR_CATALOG[vendor].get("snapshot_paths", [])[:2]:
                        path = snap_path.replace("{ch}", "1")
                        thumb_path = ThumbnailCapture.grab_http(ip, port, path)
                        if thumb_path:
                            break
                if thumb_path:
                    item["thumbnail"] = thumb_path
                    self.log("  📸 Thumbnail captured", "ok")

            if item.get("asset_id"):
                update_data = {k: item[k] for k in [
                    "ip", "vendor", "access_level", "has_password", "status",
                    "auth_user", "auth_pass", "thumbnail", "rtsp_ok",
                ] if k in item}
                self.db.upsert_asset(update_data, self.scope_mgr)

            time.sleep(random.uniform(0.5, 2.0))

    def _match_vendor(self, data: Dict[str, Any]) -> str:
        banner = (data.get("banner") or "").lower()
        http_title = (data.get("http_title") or "").lower()
        oui = data.get("oui", "")
        combined = f"{banner} {http_title}"
        if data.get("onvif_data"):
            for scope in data["onvif_data"].get("scopes", []):
                combined += f" {scope.lower()}"
        if data.get("ssdp_data"):
            combined += f" {data['ssdp_data'].get('location', '').lower()}"
        for vendor, catalog in VENDOR_CATALOG.items():
            for fp in catalog.get("fingerprint", []):
                if fp.lower() in combined:
                    return vendor
            if oui:
                for prefix in catalog.get("oui_prefixes", []):
                    if oui.lower().startswith(prefix.lower()):
                        return vendor
        return "Unknown"

    def _extract_model(self, data: Dict[str, Any]) -> str:
        banner = data.get("banner", "") or ""
        http_title = data.get("http_title", "") or ""
        vendor = data.get("vendor", "")
        if vendor in VENDOR_CATALOG:
            for pattern in VENDOR_CATALOG[vendor].get("model_patterns", []):
                match = re.search(pattern, f"{banner} {http_title}", re.IGNORECASE)
                if match:
                    return match.group(0)
        return ""

    def _extract_firmware(self, data: Dict[str, Any]) -> str:
        banner = data.get("banner", "") or ""
        for pattern in [r"v([\d.]+)", r"firmware[:\s]+([\d.]+)", r"Version[:\s]+([\d.]+)"]:
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                return match.group(1)
        return ""

    def _extract_oui(self, data: Dict[str, Any]) -> str:
        mac = data.get("mac", "")
        if mac and len(mac) >= 8:
            return mac[:8].replace("-", ":").lower()
        return ""

    def _classify_camera(self, data: Dict[str, Any]) -> str:
        camera_types = {
            "webcam": ["webcam", "USB Camera", "HD Webcam", "Logitech"],
            "cctv_outdoor": ["CCTV", "outdoor", "surveillance", "bullet", "IP Camera"],
            "cctv_indoor": ["indoor", "dome", "PTZ", "baby monitor"],
            "traffic": ["traffic", "ANPR", "license plate", "road"],
            "ptz": ["PTZ", "pan-tilt", "speed dome"],
            "thermal": ["thermal", "infrared"],
            "doorbell": ["doorbell", "ring", "video doorbell"],
        }
        combined = f"{data.get('banner', '')} {data.get('http_title', '')}".lower()
        for cam_type, keywords in camera_types.items():
            for kw in keywords:
                if kw.lower() in combined:
                    return cam_type
        return "unknown"

    def stop(self) -> None:
        self.running = False


# ═══════════════════════════════════════════════════════════════
# FLASK DASHBOARD
# ═══════════════════════════════════════════════════════════════

app = Flask(__name__)
active_orchestrator: Optional[DiscoveryOrchestrator] = None

DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Oculux v7.4</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"/>
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;700&family=Inter:wght@300;400;500;600;700&display=swap');
:root{--bg0:#080c14;--bg1:#0f1623;--bg2:#182234;--brd:#243044;--tx1:#e2e8f0;--tx2:#8899ad;--acc:#0ea5e9;--acc2:rgba(14,165,233,.12);--dng:#ef4444;--suc:#22c55e;--wrn:#eab308;--prp:#a855f7;--cyn:#06b6d4}
*{margin:0;padding:0;box-sizing:border-box}body{font-family:'Inter',sans-serif;background:var(--bg0);color:var(--tx1);min-height:100vh}
.hdr{background:var(--bg1);border-bottom:1px solid var(--brd);padding:.6rem 1.5rem;display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:100}
.logo{font-family:'JetBrains Mono',monospace;font-size:1.1rem;font-weight:700;color:var(--acc)}.logo span{color:var(--tx2);font-weight:300;font-size:.7rem}
.nav{display:flex;gap:0}.ntab{padding:.4rem .75rem;color:var(--tx2);font-size:.74rem;cursor:pointer;border-bottom:2px solid transparent;transition:.2s;font-weight:500}.ntab:hover{color:var(--tx1)}.ntab.on{color:var(--acc);border-bottom-color:var(--acc)}
.wrap{max-width:1500px;margin:0 auto;padding:1.1rem}
.pg{display:none}.pg.on{display:block}
.cd{background:var(--bg2);border:1px solid var(--brd);border-radius:8px;padding:1rem;margin-bottom:1rem}
.cd h3{font-size:.78rem;color:var(--tx2);margin-bottom:.6rem;font-weight:500}
.sg{display:grid;grid-template-columns:repeat(auto-fit,minmax(145px,1fr));gap:.65rem;margin-bottom:1.1rem}
.sc{background:var(--bg2);border:1px solid var(--brd);border-radius:8px;padding:.75rem;cursor:pointer;transition:.2s}.sc:hover{border-color:var(--acc)}
.sl{font-size:.56rem;color:var(--tx2);text-transform:uppercase;letter-spacing:1px;margin-bottom:.2rem}
.sv{font-family:'JetBrains Mono',monospace;font-size:1.25rem;font-weight:700}
.sv.a{color:var(--acc)}.sv.d{color:var(--dng)}.sv.s{color:var(--suc)}.sv.w{color:var(--wrn)}.sv.p{color:var(--prp)}.sv.c{color:var(--cyn)}
.fg{display:flex;flex-direction:column;margin-bottom:.4rem}
.fg label{font-size:.56rem;color:var(--tx2);text-transform:uppercase;letter-spacing:.5px;margin-bottom:.15rem;font-weight:500}
.fg input,.fg select,.fg textarea{padding:.35rem .5rem;background:var(--bg0);border:1px solid var(--brd);border-radius:4px;color:var(--tx1);font-family:'JetBrains Mono',monospace;font-size:.74rem}
.fg input:focus,.fg select:focus{outline:none;border-color:var(--acc);box-shadow:0 0 0 2px var(--acc2)}
.bt{padding:.35rem .85rem;border:none;border-radius:4px;font-weight:500;font-size:.74rem;cursor:pointer;transition:.2s;white-space:nowrap;font-family:'Inter',sans-serif}
.b1{background:var(--acc);color:var(--bg0)}.b1:hover{background:#0284c7}.bd{background:var(--dng);color:#fff}.bp{background:var(--prp);color:#fff}.bc{background:var(--cyn);color:var(--bg0)}
.bs{padding:.2rem .4rem;font-size:.64rem}
.fb{display:flex;gap:.35rem;margin-bottom:.6rem;flex-wrap:wrap;align-items:center}
.fc{padding:.15rem .5rem;border-radius:9999px;font-size:.6rem;background:var(--bg0);border:1px solid var(--brd);color:var(--tx2);cursor:pointer;transition:.2s;font-family:'JetBrains Mono',monospace}
.fc:hover,.fc.on{border-color:var(--acc);color:var(--acc);background:var(--acc2)}
.cr{display:grid;grid-template-columns:1fr 1fr 1fr;gap:.65rem;margin-bottom:1.1rem}
#mapC{height:320px;border-radius:6px;overflow:hidden;margin-bottom:1.1rem}
table{width:100%;border-collapse:collapse}
th{padding:.4rem .55rem;text-align:left;font-size:.56rem;color:var(--tx2);text-transform:uppercase;letter-spacing:1px;border-bottom:1px solid var(--brd);background:rgba(0,0,0,.2)}
td{padding:.4rem .55rem;font-size:.68rem;font-family:'JetBrains Mono',monospace;border-bottom:1px solid rgba(36,48,68,.5)}
tr:hover{background:rgba(14,165,233,.04)}
.bg{padding:.1rem .28rem;border-radius:3px;font-size:.54rem;font-weight:600;font-family:'JetBrains Mono',monospace}
.bv{background:rgba(239,68,68,.12);color:var(--dng)}.bw{background:rgba(234,179,8,.12);color:var(--wrn)}.bm{background:rgba(14,165,233,.12);color:var(--acc)}.bgs{background:rgba(34,197,94,.12);color:var(--suc)}.bx{background:rgba(168,85,247,.12);color:var(--prp)}.bc2{background:rgba(6,182,212,.12);color:var(--cyn)}
.log{background:var(--bg0);border:1px solid var(--brd);border-radius:6px;padding:.6rem;max-height:200px;overflow-y:auto;font-family:'JetBrains Mono',monospace;font-size:.66rem;color:var(--tx2);line-height:1.5}
.log .ok{color:var(--suc)}.log .err{color:var(--dng)}.log .warn{color:var(--wrn)}.log .info{color:var(--acc)}
.cvg{display:grid;grid-template-columns:repeat(auto-fill,minmax(290px,1fr));gap:.65rem}
.cv{background:var(--bg0);border:1px solid var(--brd);border-radius:6px;padding:.75rem;transition:.2s}.cv:hover{border-color:var(--acc)}
.ci{font-family:'JetBrains Mono',monospace;color:var(--acc);font-size:.74rem;font-weight:600}
.ct{font-size:.78rem;margin:.2rem 0;font-weight:500}.cd2{font-size:.68rem;color:var(--tx2);margin-top:.25rem;line-height:1.4}
.cm{display:flex;gap:.25rem;margin-top:.25rem;align-items:center;flex-wrap:wrap}
.em{text-align:center;padding:1.8rem;color:var(--tx2)}
.toast{position:fixed;bottom:1.3rem;right:1.3rem;padding:.55rem .9rem;background:var(--bg2);border:1px solid var(--acc);border-radius:6px;color:var(--tx1);font-size:.74rem;z-index:9999;opacity:0;transform:translateY(.7rem);transition:.3s}.toast.show{opacity:1;transform:translateY(0)}
.modal{display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,.7);z-index:1000;justify-content:center;align-items:center}.modal.show{display:flex}
.mcont{background:var(--bg2);border:1px solid var(--brd);border-radius:10px;width:92%;max-width:750px;max-height:80vh;overflow-y:auto;padding:1.2rem}
.mcont h2{color:var(--acc);font-size:.9rem;margin-bottom:.7rem;font-family:'JetBrains Mono',monospace}
.drow{display:grid;grid-template-columns:120px 1fr;gap:.35rem;margin-bottom:.35rem;font-size:.76rem}.dl{color:var(--tx2);font-weight:500}.dv{font-family:'JetBrains Mono',monospace;word-break:break-all}
.cbar{height:5px;border-radius:3px;background:var(--bg0);overflow:hidden;margin-top:.2rem}.cfill{height:100%;border-radius:3px;transition:width .3s}
.thumb{max-width:280px;border-radius:6px;border:1px solid var(--brd);margin-top:.5rem}
@media(max-width:1024px){.cr{grid-template-columns:1fr 1fr}}@media(max-width:768px){.cr{grid-template-columns:1fr}}
</style>
</head>
<body>
<div class="hdr">
<div class="logo">OCULUX <span>v7.4 // defensive verification</span></div>
<div class="nav">
<div class="ntab on" onclick="pg('dash',this)">Dashboard</div>
<div class="ntab" onclick="pg('assets',this)">Assets</div>
<div class="ntab" onclick="pg('vulns',this)">CVEs</div>
<div class="ntab" onclick="pg('scope',this)">Scope</div>
<div class="ntab" onclick="pg('tools',this)">Tools</div>
<div class="ntab" onclick="pg('cfg',this)">Config</div>
</div>
</div>
<div class="wrap">

<!-- DASHBOARD -->
<div id="pg-dash" class="pg on">
<div style="display:grid;grid-template-columns:2fr 1fr 1fr 1fr auto auto;gap:.4rem;align-items:end;margin-bottom:.35rem">
<div class="fg"><label>Targets (CIDR/IP/IP:PORT/Domain)</label><input id="tgt" placeholder="192.168.1.0/24 or 192.168.1.10:8554" value="192.168.1.0/24"></div>
<div class="fg"><label>Mode</label><select id="mode"><option value="stealth">Stealth</option><option value="quiet">Quiet</option><option value="medium" selected>Medium</option><option value="aggressive">Aggressive</option><option value="war">War</option><option value="nuke">Nuke</option></select></div>
<div class="fg"><label>Sources</label><select id="src"><option value="all">All Sources</option><option value="passive">Passive Only</option><option value="internet">Internet Only</option><option value="local">Local Only</option><option value="tcp">Built-in TCP</option><option value="fofa">FOFA</option><option value="zoomeye">ZoomEye</option><option value="shodan">Shodan</option><option value="masscan">Masscan</option><option value="onvif">ONVIF</option></select></div>
<div class="fg"><label>Options</label><select id="opts"><option value="discover" selected>Discover Only</option><option value="no_creds">Identify Only</option><option value="default_audit">Default Password Audit</option><option value="full">Full Pipeline</option></select></div>
<button class="bt b1" id="goBtn" onclick="go()">Discover</button>
<button class="bt bd" id="stopBtn" onclick="stop()" style="display:none">Stop</button>
</div>
<label style="display:flex;gap:.45rem;align-items:center;margin-bottom:.8rem;color:var(--tx2);font-size:.68rem"><input id="lgConfirm" type="checkbox"> I confirm this scan is authorized and may cover a large IP range or Masscan sweep.</label>

<div class="sg">
<div class="sc" onclick="fA('all')"><div class="sl">Total Assets</div><div class="sv a" id="sT">0</div></div>
<div class="sc" onclick="fA('no_pass')"><div class="sl">🔓 No Password</div><div class="sv s" id="sNP">0</div></div>
<div class="sc" onclick="fA('default')"><div class="sl">🔑 Default</div><div class="sv w" id="sDC">0</div></div>
<div class="sc" onclick="fA('crack')"><div class="sl">🔒 Needs Crack</div><div class="sv p" id="sNC">0</div></div>
<div class="sc" onclick="fA('vuln')"><div class="sl">⚠️ Vulnerable</div><div class="sv d" id="sV">0</div></div>
<div class="sc"><div class="sl">Avg Confidence</div><div class="sv c" id="sCon">0%</div></div>
<div class="sc"><div class="sl">Fresh</div><div class="sv s" id="sFr">0</div></div>
<div class="sc"><div class="sl">Stale</div><div class="sv w" id="sSt">0</div></div>
</div>

<div class="log" id="sLog">Ready. Select mode and discover.</div>
<div id="mapC"></div>
<div class="cr">
<div class="cd"><h3>Vendor Distribution</h3><canvas id="chV"></canvas></div>
<div class="cd"><h3>Discovery Sources</h3><canvas id="chS"></canvas></div>
<div class="cd"><h3>Confidence Distribution</h3><canvas id="chC"></canvas></div>
</div>
</div>

<!-- ASSETS -->
<div id="pg-assets" class="pg">
<div class="fb" id="aF">
<span style="font-size:.64rem;color:var(--tx2)">FILTER:</span>
<div class="fc on" onclick="fA('all',this)">All</div>
<div class="fc" onclick="fA('no_pass',this)">🔓 No Pass</div>
<div class="fc" onclick="fA('default',this)">🔑 Default</div>
<div class="fc" onclick="fA('crack',this)">🔒 Crack</div>
<div class="fc" onclick="fA('vuln',this)">⚠️ Vulnerable</div>
<input type="text" id="aS" placeholder="Search..." style="margin-left:auto;padding:.2rem .4rem;background:var(--bg0);border:1px solid var(--brd);border-radius:4px;color:var(--tx1);font-size:.68rem;font-family:'JetBrains Mono',monospace;width:170px" oninput="lA()">
</div>
<div class="cd" style="padding:0;overflow:hidden">
<div style="padding:.5rem .7rem;border-bottom:1px solid var(--brd);display:flex;justify-content:space-between;align-items:center">
<h3 style="margin:0">Assets</h3>
<div><button class="bt bs bp" onclick="expCSV()">CSV</button><span id="aCt" style="color:var(--tx2);font-size:.66rem;margin-left:.3rem"></span></div>
</div>
<div style="overflow-x:auto"><table><thead><tr><th>IP</th><th>Port</th><th>Vendor</th><th>Model</th><th>Confidence</th><th>Class</th><th>Access</th><th>Source</th><th>Fresh</th><th>Actions</th></tr></thead>
<tbody id="aTB"><tr><td colspan="10" class="em">No assets. Run discovery first.</td></tr></tbody></table></div>
</div>
</div>

<!-- VULNS -->
<div id="pg-vulns" class="pg">
<div class="sg"><div class="sc"><div class="sl">Critical</div><div class="sv d" id="vC">0</div></div><div class="sc"><div class="sl">High</div><div class="sv w" id="vH">0</div></div><div class="sc"><div class="sl">Medium</div><div class="sv a" id="vM">0</div></div><div class="sc"><div class="sl">Low</div><div class="sv s" id="vL">0</div></div></div>
<div class="fb" id="vF"><span style="font-size:.64rem;color:var(--tx2)">VENDOR:</span></div>
<div class="cvg" id="vG"></div>
</div>

<!-- SCOPE -->
<div id="pg-scope" class="pg">
<div class="cd"><h3>🎯 Scope</h3>
<div style="display:grid;grid-template-columns:1fr 1fr;gap:.6rem">
<div><div class="fg"><label>CIDR</label><input id="sCidr" placeholder="192.168.1.0/24"></div><button class="bt bs b1" onclick="addSc('cidr')">Add</button></div>
<div><div class="fg"><label>Domain</label><input id="sDom" placeholder="cam.corp.com"></div><button class="bt bs b1" onclick="addSc('domain')">Add</button></div>
<div><div class="fg"><label>ASN</label><input id="sAsn" placeholder="AS12345"></div><button class="bt bs b1" onclick="addSc('asn')">Add</button></div>
<div><div class="fg"><label>IP Range</label><div style="display:flex;gap:.2rem"><input id="sIpS" placeholder="Start" style="flex:1"><input id="sIpE" placeholder="End" style="flex:1"></div></div><button class="bt bs b1" onclick="addSc('range')">Add</button></div>
</div></div>
<div class="cd"><h3>Current Scope</h3><div id="scL" style="font-family:'JetBrains Mono',monospace;font-size:.7rem;color:var(--tx2)"></div></div>
<div class="cd"><h3>🚫 Blocklist</h3>
<div class="fg"><label>Block IP</label><div style="display:flex;gap:.2rem"><input id="bIp" placeholder="1.2.3.4"><button class="bt bs bd" onclick="addBl()">Block</button></div></div>
<div id="blL" style="font-family:'JetBrains Mono',monospace;font-size:.7rem;color:var(--tx2);margin-top:.4rem"></div>
</div>
</div>

<!-- TOOLS -->
<div id="pg-tools" class="pg">
<div style="display:grid;grid-template-columns:1fr 1fr;gap:.7rem">
<div class="cd"><h3>🔧 Installed Tools</h3><div id="tSt"></div></div>
<div class="cd"><h3>🔓 Hydra — Credential Cracking</h3>
<div class="fg"><label>Asset ID</label><input id="crId" placeholder="Asset ID"></div>
<div class="fg"><label>Protocol</label><select id="crP"><option value="http">HTTP</option><option value="rtsp">RTSP</option></select></div>
<div class="fg"><label>Threads</label><input id="crT" type="number" value="4" min="1" max="16"></div>
<button class="bt b1" onclick="crack()">Crack</button>
</div></div>
<div class="cd"><h3>Metasploit - Manual Execution</h3>
<div style="display:grid;grid-template-columns:2fr 1fr 1fr auto;gap:.4rem;align-items:end">
<div class="fg"><label>Module</label><input id="msfMod" placeholder="exploit/linux/http/hikvision_cve_2021_36260"></div>
<div class="fg"><label>Port</label><input id="msfPort" placeholder="80"></div>
<div class="fg"><label>Asset ID</label><input id="msfAid"></div>
<button class="bt bp" onclick="runMsf()">Run</button>
</div>
<p style="font-size:.64rem;color:var(--tx2);line-height:1.5;margin-top:.45rem">Disabled by default. CVE assessment uses Metasploit module names as references without running them.</p></div>
<div class="cd"><h3>📋 Jobs</h3>
<table><thead><tr><th>ID</th><th>Asset</th><th>Tool</th><th>Status</th><th>Result</th><th>Started</th></tr></thead>
<tbody id="jTB"><tr><td colspan="6" class="em">No jobs.</td></tr></tbody></table></div>
</div>

<!-- CONFIG -->
<div id="pg-cfg" class="pg">
<div style="display:grid;grid-template-columns:1fr 1fr;gap:.7rem">
<div class="cd"><h3>🌐 Proxy</h3>
<div class="fg"><label>Type</label><select id="pxT"><option value="">None</option><option value="socks5">SOCKS5</option><option value="http">HTTP</option></select></div>
<div class="fg"><label>Host</label><input id="pxH" placeholder="127.0.0.1"></div>
<div class="fg"><label>Port</label><input id="pxP" placeholder="9050"></div>
<div class="fg"><label>User</label><input id="pxU"></div>
<div class="fg"><label>Pass</label><input id="pxPw" type="password"></div>
<button class="bt b1" onclick="savePx()">Save</button><button class="bt bd" onclick="clrPx()" style="margin-left:.3rem">Clear</button>
</div>
<div class="cd">
<h3>💾 Data</h3>
<div style="display:flex;gap:.3rem;margin-top:.4rem;flex-wrap:wrap">
<button class="bt b1" onclick="expCSV()">CSV</button><button class="bt bp" onclick="expDB()">DB</button>
<button class="bt bd" onclick="clrDB()">Clear</button><button class="bt bc" onclick="dec()">Decay</button>
</div>
<h3 style="margin-top:.8rem">📖 Install</h3>
<div style="font-family:'JetBrains Mono',monospace;font-size:.7rem;color:var(--tx2);line-height:1.6">
<p><b style="color:var(--acc)">httpx:</b> pip install httpx</p>
<p><b style="color:var(--acc)">shodan:</b> pip install shodan</p>
<p><b style="color:var(--acc)">masscan:</b> sudo apt install masscan</p>
<p><b style="color:var(--acc)">nmap:</b> sudo apt install nmap</p>
<p><b style="color:var(--acc)">hydra:</b> sudo apt install hydra</p>
<p><b style="color:var(--acc)">searchsploit:</b> install Exploit-DB SearchSploit</p>
<p><b style="color:var(--acc)">metasploit:</b> sudo apt install metasploit-framework</p>
<p><b style="color:var(--acc)">ffmpeg:</b> sudo apt install ffmpeg</p>
<p><b style="color:var(--acc)">dns:</b> pip install dnspython</p>
</div></div></div>
</div>
</div>

<div class="modal" id="aMod"><div class="mcont" id="aMC"></div></div>
<div class="toast" id="toast"></div>

<script>
let chV,chS,chC,map,mks=[],pollI;
function esc(s) {
    if (s == null) return '';
    return String(s)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}
function pg(n,el){document.querySelectorAll('.pg').forEach(p=>p.classList.remove('on'));document.querySelectorAll('.ntab').forEach(t=>t.classList.remove('on'));document.getElementById('pg-'+n).classList.add('on');el.classList.add('on');if(n==='assets')lA();if(n==='vulns')lV();if(n==='scope')lSc();if(n==='tools')lT();}
function toast(m){const t=document.getElementById('toast');t.textContent=m;t.classList.add('show');setTimeout(()=>t.classList.remove('show'),3000);}
function initMap(){map=L.map('mapC').setView([20,0],2);L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png',{attribution:'&copy; OSM &copy; CARTO',maxZoom:18}).addTo(map);}
function initCharts(){
const o={responsive:true,plugins:{legend:{labels:{color:'#8899ad',font:{size:9}}}}};
chV=new Chart(document.getElementById('chV'),{type:'doughnut',data:{labels:[],datasets:[{data:[],backgroundColor:['#0ea5e9','#22c55e','#eab308','#ef4444','#a855f7','#ec4899','#6366f1','#14b8a6'],borderColor:'#182234',borderWidth:2}]},options:o});
chS=new Chart(document.getElementById('chS'),{type:'doughnut',data:{labels:[],datasets:[{data:[],backgroundColor:['#06b6d4','#0ea5e9','#8b5cf6','#22c55e','#f59e0b','#ef4444','#a855f7'],borderColor:'#182234',borderWidth:2}]},options:o});
chC=new Chart(document.getElementById('chC'),{type:'bar',data:{labels:['0-20%','21-40%','41-60%','61-80%','81-100%'],datasets:[{label:'Assets',data:[0,0,0,0,0],backgroundColor:['#ef4444','#f59e0b','#eab308','#22c55e','#0ea5e9'],borderRadius:4}]},options:{...o,scales:{x:{ticks:{color:'#8899ad'},grid:{color:'rgba(36,48,68,.3)'}},y:{ticks:{color:'#8899ad'},grid:{color:'rgba(36,48,68,.3)'}}}}});
}

async function rSt(){
const r=await fetch('/api/stats');const s=await r.json();
document.getElementById('sT').textContent=s.total_assets;
document.getElementById('sNP').textContent=s.no_password;
document.getElementById('sDC').textContent=s.default_creds;
document.getElementById('sNC').textContent=s.needs_cracking;
document.getElementById('sV').textContent=s.vulnerable;
document.getElementById('sCon').textContent=(s.avg_confidence||0)+'%';
document.getElementById('sFr').textContent=s.fresh;
document.getElementById('sSt').textContent=s.stale;
chV.data.labels=Object.keys(s.by_vendor||{});chV.data.datasets[0].data=Object.values(s.by_vendor||{});chV.update();
chS.data.labels=Object.keys(s.by_source||{});chS.data.datasets[0].data=Object.values(s.by_source||{});chS.update();
const ar=await fetch('/api/assets?limit=1000');const as=await ar.json();
const bins=[0,0,0,0,0];as.forEach(a=>{const c=a.confidence||0;if(c<=20)bins[0]++;else if(c<=40)bins[1]++;else if(c<=60)bins[2]++;else if(c<=80)bins[3]++;else bins[4]++;});
chC.data.datasets[0].data=bins;chC.update();
uMap(as);
}

function uMap(as){mks.forEach(m=>map.removeLayer(m));mks=[];as.forEach(a=>{if(a.latitude&&a.longitude){const col=a.access_level==='full'?'#22c55e':a.access_level==='default'?'#eab308':'#a855f7';const mk=L.circleMarker([a.latitude,a.longitude],{radius:5,fillColor:col,color:col,weight:1,opacity:.8,fillOpacity:.6}).addTo(map).bindPopup(`<b>${a.primary_ip}:${a.primary_port||''}</b><br>${a.vendor||'?'} ${a.model||''}<br>Conf: ${a.confidence||0}%<br>Class: ${a.classification||'?'}<br>Access: ${a.access_level}`);mks.push(mk);}});}

async function go(){
const t=document.getElementById('tgt').value;const m=document.getElementById('mode').value;const s=document.getElementById('src').value;const o=document.getElementById('opts').value;
const lc=document.getElementById('lgConfirm').checked;
document.getElementById('goBtn').style.display='none';document.getElementById('stopBtn').style.display='inline-block';
const r=await fetch('/api/scan/start',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({target:t,mode:m,sources:s,options:o,confirm_large:lc})});
if(r.ok){toast('Discovery started');pollI=setInterval(poll,1500);}
else{const d=await r.json().catch(()=>({message:'Unable to start scan'}));document.getElementById('goBtn').style.display='inline-block';document.getElementById('stopBtn').style.display='none';toast(d.message||'Unable to start scan');}
}
async function stop(){await fetch('/api/scan/stop',{method:'POST'});clearInterval(pollI);document.getElementById('goBtn').style.display='inline-block';document.getElementById('stopBtn').style.display='none';toast('Stopped');}

async function poll(){
const r=await fetch('/api/scan/status');const d=await r.json();
document.getElementById('sLog').innerHTML=d.progress.map(l=>{let c='info';if(l.includes('✓'))c='ok';if(l.includes('✗'))c='err';if(l.includes('⚠'))c='warn';return `<div class="${c}">${l}</div>`;}).join('');
const log=document.getElementById('sLog');log.scrollTop=log.scrollHeight;
if(!d.running&&d.progress.length>1){clearInterval(pollI);document.getElementById('goBtn').style.display='inline-block';document.getElementById('stopBtn').style.display='none';toast(`Done: ${d.stats?.identified||0} identified`);}
rSt();
}

let aFilter='all';
async function lA(f){
if(f)aFilter=f;
const r=await fetch(`/api/assets?filter=${aFilter}&search=${document.getElementById('aS')?.value||''}`);const as=await r.json();
let h='';as.forEach(a=>{
const conf=a.confidence||0;const cc=conf>=80?'bgs':conf>=60?'bw':conf>=40?'bm':'bv';
const cls=a.classification||'unknown';const clsC=cls==='camera'?'bgs':cls==='likely_camera'?'bw':cls==='possible_camera'?'bm':'bv';
const al=a.access_level;let ab='',at='';
if(al==='full'){ab='bgs';at='🔓 No Pass';}else if(al==='default'){ab='bw';at='🔑 Default';}else if(al==='needs_cracking'){ab='bx';at='🔒 Crack';}else if(al==='cracked'){ab='bgs';at='🔓 Cracked';}else{ab='bm';at='?';}
const src=(a.discovery_source||'?').split(',')[0];const decay=a.decay_score||1;
const fr=decay>=0.8?'bgs':decay>=0.5?'bw':'bv';
h+=`<tr><td>${esc(a.primary_ip)}</td><td>${esc(a.primary_port)||'-'}</td><td>${esc(a.vendor)||'?'}</td><td>${esc(a.model)||'-'}</td>
<td><span class="bg ${cc}">${esc(conf)}%</span><div class="cbar"><div class="cfill" style="width:${esc(conf)}%;background:${conf>=80?'#22c55e':conf>=60?'#eab308':'#ef4444'}"></div></div></td>
<td><span class="bg ${clsC}">${esc(cls.replace('_',' '))}</span></td>
<td><span class="bg ${ab}">${esc(at)}</span></td><td><span class="bg bc2">${esc(src)}</span></td>
<td><span class="bg ${fr}">${esc((decay*100).toFixed(0))}%</span></td>
<td><button class="bt bs b1" onclick="vA(${esc(a.id)})">View</button>${al==='needs_cracking'?`<button class="bt bs bp" onclick="crById(${esc(a.id)})">Crack</button>`:''}</td></tr>`;
});
document.getElementById('aTB').innerHTML=h||'<tr><td colspan="10" class="em">No assets.</td></tr>';
document.getElementById('aCt').textContent=`${as.length}`;
}

function fA(f,el){if(el){document.querySelectorAll('#aF .fc').forEach(c=>c.classList.remove('on'));el.classList.add('on');}lA(f);}

function arr(v){
if(Array.isArray(v))return v;
if(!v)return [];
if(typeof v==='string'){
try{const p=JSON.parse(v);return Array.isArray(p)?p:[];}catch(e){return v.match(/CVE-\\d{4}-\\d{4,}/gi)||[];}
}
return [];
}
function sevClass(sev){
const s=String(sev||'').toUpperCase();
if(s==='CRITICAL')return 'bv';
if(s==='HIGH')return 'bw';
if(s==='MEDIUM')return 'bm';
return 'bgs';
}
function renderLinks(urls,label){
const vals=arr(urls).filter(u=>String(u).startsWith('http')).slice(0,5);
if(!vals.length)return '';
return `<div style="margin-top:.35rem;font-size:.62rem;color:var(--tx2)">${label}: ${vals.map((u,i)=>`<a href="${esc(u)}" target="_blank" rel="noopener noreferrer" style="color:var(--acc)">ref ${i+1}</a>`).join(' ')}</div>`;
}
function renderFinding(f){
const evidence=arr(f.evidence).slice(0,6);
const edb=arr(f.exploitdb_refs).filter(e=>String(e.url||'').startsWith('http')).slice(0,5);
const msf=arr(f.metasploit_modules).slice(0,5);
let h=`<div class="cv"><div class="ci">${esc(f.cve_id)}</div><div class="ct">${esc(f.title||f.cve_id)}</div>`;
h+=`<div class="cm"><span class="bg ${sevClass(f.severity)}">${esc(f.severity||'UNKNOWN')}</span><span style="color:var(--tx2);font-size:.6rem;font-family:'JetBrains Mono',monospace">CVSS ${esc(f.cvss||0)}</span><span class="bg bm">${esc(f.confidence||0)}% confidence</span>${f.known_exploited?'<span class="bg bv">CISA KEV</span>':''}</div>`;
h+=`<div class="cd2"><b style="color:var(--tx1)">Assessment:</b> ${esc(f.assessment||'Review required')}</div>`;
if(f.description)h+=`<div class="cd2">${esc(String(f.description).slice(0,420))}</div>`;
if(evidence.length)h+=`<div style="margin-top:.35rem;font-size:.64rem;color:var(--tx2);line-height:1.45"><b style="color:var(--tx1)">Evidence</b>${evidence.map(e=>`<div>- ${esc(e)}</div>`).join('')}</div>`;
if(f.remediation)h+=`<div style="margin-top:.35rem;font-size:.64rem;color:var(--suc);line-height:1.45"><b>Fix:</b> ${esc(f.remediation)}</div>`;
if(edb.length)h+=`<div style="margin-top:.35rem;font-size:.62rem;color:var(--tx2)">Exploit-DB refs: ${edb.map(e=>`<a href="${esc(e.url)}" target="_blank" rel="noopener noreferrer" style="color:var(--wrn)">${esc(e.id||'entry')}</a>`).join(' ')}</div>`;
if(msf.length)h+=`<div style="margin-top:.25rem;font-size:.62rem;color:var(--prp)">Metasploit refs: ${msf.map(m=>`<span style="font-family:'JetBrains Mono',monospace">${esc(m)}</span>`).join(' ')}</div>`;
h+=renderLinks(f.reference_urls,'Sources');
h+=`</div>`;
return h;
}

async function vA(id){
const r=await fetch(`/api/asset/${id}`);const a=await r.json();
const svcs=await (await fetch(`/api/asset/${id}/services`)).json();
const findings=await (await fetch(`/api/asset/${id}/findings`)).json();
const cves=[...new Set([...arr(a.cves),...svcs.flatMap(s=>arr(s.cves))].map(String).filter(Boolean))];
const reasons=JSON.parse(a.confidence_reasons||'{}');
let h=`<h2>${esc(a.primary_ip)} — ${esc(a.vendor)||'?'} ${esc(a.model)||''}</h2>`;
h+=`<div class="drow"><div class="dl">Confidence</div><div class="dv">${esc(a.confidence)||0}% <span class="bg ${a.classification==='camera'?'bgs':a.classification==='likely_camera'?'bw':'bv'}">${esc(a.classification)||'unknown'}</span></div></div>`;
const rKeys=Object.keys(reasons).filter(k=>!k.startsWith('_'));
if(rKeys.length){h+=`<div style="font-size:.7rem;color:var(--tx2);margin-bottom:.5rem;padding-left:120px">`;rKeys.forEach(k=>{h+=`<div>• ${esc(k)}: ${esc(reasons[k])}</div>`;});h+=`</div>`;}
h+=`<div class="drow"><div class="dl">Access</div><div class="dv">${esc(a.access_level)}</div></div>`;
h+=`<div class="drow"><div class="dl">Firmware</div><div class="dv">${esc(a.firmware)||'Unknown'}</div></div>`;
h+=`<div class="drow"><div class="dl">Decay</div><div class="dv">${esc(((a.decay_score||1)*100).toFixed(0))}%</div></div>`;
h+=`<div class="drow"><div class="dl">First Seen</div><div class="dv">${esc(a.first_seen)||'-'}</div></div>`;
h+=`<div class="drow"><div class="dl">Last Verified</div><div class="dv">${esc(a.last_verified)||'Never'}</div></div>`;
h+=`<div class="drow"><div class="dl">Verify Count</div><div class="dv">${esc(a.verify_count)||0}</div></div>`;
h+=`<div class="drow"><div class="dl">Source</div><div class="dv">${esc(a.discovery_source)||'-'}</div></div>`;
h+=`<div class="drow"><div class="dl">OUI</div><div class="dv">${esc(a.oui)||'-'}</div></div>`;
h+=`<div class="drow"><div class="dl">Country / Org</div><div class="dv">${esc(a.country)||'-'} / ${esc(a.org)||'-'}</div></div>`;
h+=`<h3 style="margin-top:.8rem;color:var(--acc);font-size:.82rem">Services (${esc(svcs.length)})</h3>`;
svcs.forEach(s=>{h+=`<div style="padding:.25rem 0;font-size:.72rem;border-bottom:1px solid var(--brd)"><b>${esc(s.ip)}:${esc(s.port)}</b> — ${esc(s.service_type)||esc(s.protocol)||'?'}${s.banner?'<br><small style="color:var(--tx2)">'+esc(s.banner.substring(0,120))+'</small>':''}</div>`;});
h+=`<h3 style="margin-top:.8rem;color:var(--dng);font-size:.82rem">CVEs (${esc(cves.length)})</h3>`;
cves.forEach(cv=>{h+=`<div style="padding:.15rem 0;font-size:.72rem"><span style="color:var(--acc);font-family:'JetBrains Mono',monospace">${esc(cv)}</span></div>`;});
h+=`<h3 style="margin-top:.8rem;color:var(--wrn);font-size:.82rem">Assessment findings (${esc(findings.length)})</h3>`;
h+=findings.length?findings.map(renderFinding).join(''):`<div class="em" style="padding:.7rem">No defensive assessment saved yet.</div>`;
if(a.thumbnail){h+=`<h3 style="margin-top:.8rem;color:var(--suc);font-size:.82rem">📸 Thumbnail</h3><img class="thumb" src="/thumbnails/${esc(a.thumbnail.split('/').pop())}">`;}
h+=`<div style="margin-top:1rem">`;
h+=`<button class="bt b1" onclick="window.open('http://${esc(a.primary_ip)}:${esc(a.primary_port)||80}','_blank')">Open</button>`;
if(a.vendor&&String(a.vendor).toLowerCase()!=='unknown')h+=`<button class="bt bp" id="assess-${esc(a.id)}" onclick="assessAsset(${esc(a.id)})" style="margin-left:.3rem">Assess CVEs</button>`;
h+=`<button class="bt b1" id="defaults-${esc(a.id)}" onclick="testDefaults(${esc(a.id)})" style="margin-left:.3rem">Test Defaults</button>`;
h+=`<button class="bt bc" onclick="window.open('/api/asset/${esc(a.id)}/report?download=1','_blank')" style="margin-left:.3rem">JSON Report</button>`;
if(a.access_level==='needs_cracking')h+=`<button class="bt bp" onclick="crById(${esc(a.id)})" style="margin-left:.3rem">Crack</button>`;
h+=`<button class="bt bd" onclick="closeM()" style="margin-left:.3rem">Close</button></div>`;
document.getElementById('aMC').innerHTML=h;document.getElementById('aMod').classList.add('show');
}
async function pollAssessment(jobId,assetId){
for(let i=0;i<90;i++){
await new Promise(res=>setTimeout(res,2000));
const jobs=await (await fetch('/api/jobs')).json();
const job=jobs.find(j=>Number(j.id)===Number(jobId));
if(job&&['completed','error','failed','timeout'].includes(job.status)){
toast(job.status==='completed'?'Assessment complete':`Assessment ${job.status}`);
lT();await vA(assetId);return;
}
}
toast('Assessment still running; check Jobs');
lT();
}
async function assessAsset(id){
const btn=document.getElementById(`assess-${id}`);
if(btn){btn.disabled=true;btn.textContent='Assessing...';}
const r=await fetch(`/api/asset/${id}/assess`,{method:'POST'});
const d=await r.json().catch(()=>({message:'Assessment failed'}));
if(!r.ok){toast(d.message||'Assessment failed');if(btn){btn.disabled=false;btn.textContent='Assess CVEs';}return;}
toast('Assessment started');
pollAssessment(d.job_id,id);
}
async function testDefaults(id){
const btn=document.getElementById(`defaults-${id}`);
if(btn){btn.disabled=true;btn.textContent='Testing...';}
const r=await fetch(`/api/asset/${id}/test-defaults`,{method:'POST'});
const d=await r.json().catch(()=>({message:'Default-password audit failed'}));
if(!r.ok){toast(d.message||'Default-password audit failed');if(btn){btn.disabled=false;btn.textContent='Test Defaults';}return;}
toast('Default-password audit started');
pollAssessment(d.job_id,id);
}
function closeM(){document.getElementById('aMod').classList.remove('show');}
document.getElementById('aMod').onclick=function(e){if(e.target===this)closeM();};

async function lV(v){
const r=await fetch(`/api/vulns${v?'?vendor='+v:''}`);const vs=await r.json();
let cr=0,hi=0,me=0,lo=0;vs.forEach(v2=>{const s=v2.severity?.toLowerCase();if(s==='critical')cr++;else if(s==='high')hi++;else if(s==='medium')me++;else lo++;});
document.getElementById('vC').textContent=cr;document.getElementById('vH').textContent=hi;document.getElementById('vM').textContent=me;document.getElementById('vL').textContent=lo;
let h='';vs.forEach(v2=>{const sc=v2.severity==='CRITICAL'?'bv':v2.severity==='HIGH'?'bw':v2.severity==='MEDIUM'?'bm':'bgs';
h+=`<div class="cv"><div class="ci">${esc(v2.cve_id)}</div><div class="ct">${esc(v2.title)}</div><div class="cm"><span class="bg ${sc}">${esc(v2.severity)}</span><span style="color:var(--tx2);font-size:.6rem;font-family:'JetBrains Mono',monospace">CVSS ${esc(v2.cvss)}</span><span style="color:var(--prp);font-size:.6rem">${esc(v2.vendor)}</span></div><div class="cd2">${esc(v2.description)||''}</div>${v2.affected_models?`<div style="margin-top:.25rem;font-size:.62rem;color:var(--wrn)">Models: ${JSON.parse(v2.affected_models).join(', ')}</div>`:''}${v2.msf_module?`<div style="margin-top:.2rem;font-size:.62rem;color:var(--prp)">MSF: ${esc(v2.msf_module)}</div>`:''}${v2.firmware_range&&v2.firmware_range!=='any'?`<div style="font-size:.62rem;color:var(--cyn)">FW: ${esc(v2.firmware_range)}</div>`:''}</div>`;
});
document.getElementById('vG').innerHTML=h||'<div class="em">No vulns.</div>';
if(!document.getElementById('vF').dataset.init){const vendors=[...new Set(vs.map(v2=>v2.vendor))];let ch='<span style="font-size:.64rem;color:var(--tx2)">VENDOR:</span><div class="fc on" onclick="lV()">All</div>';vendors.forEach(v2=>{ch+=`<div class="fc" onclick="lV('${esc(v2)}')">${esc(v2)}</div>`;});document.getElementById('vF').innerHTML=ch;document.getElementById('vF').dataset.init='1';}
}

async function addSc(t){
const d={type:t};
if(t==='cidr')d.value=document.getElementById('sCidr').value;
else if(t==='domain')d.value=document.getElementById('sDom').value;
else if(t==='asn')d.value=document.getElementById('sAsn').value;
else if(t==='range'){d.start=document.getElementById('sIpS').value;d.end=document.getElementById('sIpE').value;}
await fetch('/api/scope',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(d)});toast('Added');lSc();
}
async function lSc(){
const r=await fetch('/api/scope');const s=await r.json();
let h='';if(s.asns?.length)h+=`<div><b>ASNs:</b> ${s.asns.join(', ')}</div>`;
if(s.domains?.length)h+=`<div><b>Domains:</b> ${s.domains.join(', ')}</div>`;
if(s.cidrs?.length)h+=`<div><b>CIDRs:</b> ${s.cidrs.join(', ')}</div>`;
h+=`<div style="margin-top:.4rem;color:var(--acc)"><b>Resolved:</b> ${s.resolved_count} IPs</div>`;
document.getElementById('scL').innerHTML=h||'No scope defined';
const br=await fetch('/api/blocklist');const bl=await br.json();
document.getElementById('blL').innerHTML=bl.map(b=>`<div>${b.ip} — ${b.reason}</div>`).join('')||'No blocked IPs';
}
async function addBl(){await fetch('/api/blocklist',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ip:document.getElementById('bIp').value})});toast('Blocked');lSc();}

async function lT(){
const r=await fetch('/api/tools');const t=await r.json();let h='';for(const[n,i]of Object.entries(t)){h+=`<div style="display:flex;justify-content:space-between;padding:.25rem 0;border-bottom:1px solid var(--brd)"><span style="font-size:.74rem;font-family:'JetBrains Mono',monospace">${n}</span><span class="bg ${i.available?'bgs':'bv'}">${i.available?'✓':'✗'}</span></div>`;}document.getElementById('tSt').innerHTML=h;
const jr=await fetch('/api/jobs');const j=await jr.json();let jh='';j.forEach(j2=>{const sc=(j2.status==='cracked'||j2.status==='completed')?'bgs':['failed','error','timeout'].includes(j2.status)?'bv':'bw';
jh+=`<tr><td>${j2.id}</td><td>${j2.asset_id||'-'}</td><td>${j2.tool}</td><td><span class="bg ${sc}">${j2.status}</span></td><td style="font-size:.65rem;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${j2.result||'-'}</td><td>${j2.started||'-'}</td></tr>`;});
document.getElementById('jTB').innerHTML=jh||'<tr><td colspan="6" class="em">No jobs.</td></tr>';
}

async function crack(){
const id=document.getElementById('crId').value;const p=document.getElementById('crP').value;const t=document.getElementById('crT').value;
if(!id){toast('Enter asset ID');return;}toast('Cracking...');
const r=await fetch('/api/crack',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({asset_id:parseInt(id),protocol:p,threads:parseInt(t)})});
const d=await r.json();toast(d.status==='started'?'Crack job started':d.message||'Error');lT();
}
async function crById(id){document.getElementById('crId').value=id;pg('tools',document.querySelectorAll('.ntab')[4]);setTimeout(()=>crack(),200);}

async function runMsf(){
const mod=document.getElementById('msfMod').value;const port=document.getElementById('msfPort').value;const aid=document.getElementById('msfAid').value;
if(!mod||!aid){toast('Enter module and asset ID');return;}
if(!confirm('Run this Metasploit module against the selected single asset? Only continue with explicit authorization.'))return;
toast('Requesting manual exploit run...');
const r=await fetch('/api/msf/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({module:mod,rport:parseInt(port),asset_id:parseInt(aid),confirmed:true})});
const d=await r.json();toast(d.status==='completed'?'Exploit completed':d.message||'Error');lT();
}

async function savePx(){await fetch('/api/proxy',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({type:document.getElementById('pxT').value,host:document.getElementById('pxH').value,port:document.getElementById('pxP').value,user:document.getElementById('pxU').value,pass:document.getElementById('pxPw').value})});toast('Saved');}
async function clrPx(){await fetch('/api/proxy',{method:'DELETE'});toast('Cleared');}
function expCSV(){window.open('/api/export/csv','_blank');}function expDB(){window.open('/api/export/db','_blank');}
async function clrDB(){if(!confirm('Clear all?'))return;await fetch('/api/db/clear',{method:'POST'});toast('Cleared');rSt();}
async function dec(){await fetch('/api/decay',{method:'POST'});toast('Decay computed');rSt();}

initMap();initCharts();rSt();lSc();
</script>
</body></html>
"""


# ═══════════════════════════════════════════════════════════════
# API ROUTES
# ═══════════════════════════════════════════════════════════════

@app.route("/")
def index():
    return render_template_string(DASHBOARD_HTML)


@app.route("/api/scan/start", methods=["POST"])
def start_scan():
    global active_orchestrator, scope_mgr
    if active_orchestrator and active_orchestrator.running:
        return jsonify({"status": "error", "message": "A scan is already running"}), 409

    data = request.json or {}
    target = data.get("target", "")
    mode = data.get("mode", "medium")
    sources_mode = data.get("sources", "all")
    options = data.get("options", "full")
    confirm_large = bool(data.get("confirm_large"))

    if mode not in MODE_CONFIG:
        return jsonify({"status": "error", "message": "Invalid scan mode"}), 400
    if sources_mode not in {"all", "passive", "internet", "local", "tcp", "fofa", "zoomeye", "shodan", "masscan", "onvif", "ssdp"}:
        return jsonify({"status": "error", "message": "Invalid discovery source"}), 400
    if options not in {"discover", "no_creds", "default_audit", "no_thumbs", "full"}:
        return jsonify({"status": "error", "message": "Invalid scan option"}), 400

    if not target.strip():
        return jsonify({"status": "error", "message": "An explicit authorized target is required"}), 400

    new_scope = ScopeManager()
    targets: List[str] = []
    custom_ports: Set[int] = set()
    estimated_hosts = 0
    has_asn_target = False
    has_large_cidr = False
    for part in target.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            host, custom_port = parse_target_spec(part)
            if custom_port:
                custom_ports.add(custom_port)
            if host.upper().startswith("AS"):
                new_scope.add_asn(host)
                has_asn_target = True
            elif "/" in host:
                network = ipaddress.ip_network(host, strict=False)
                if network.version != 4:
                    raise ValueError("IPv6 CIDR scanning is not supported by Masscan")
                canonical = str(network)
                new_scope.add_cidr(canonical)
                targets.append(canonical)
                estimated_hosts += int(network.num_addresses)
                if network.num_addresses >= 1000:
                    has_large_cidr = True
            else:
                try:
                    address = ipaddress.ip_address(host)
                    if address.version != 4:
                        raise ValueError("IPv6 targets are not supported by this scanner")
                    canonical = str(address)
                    new_scope.add_cidr(f"{canonical}/32")
                    targets.append(canonical)
                    estimated_hosts += 1
                except ValueError as exc:
                    if "IPv6" in str(exc):
                        raise
                    if not re.fullmatch(r"(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?", host):
                        raise ValueError(f"Invalid target: {host}")
                    new_scope.add_domain(host.lower())
                    targets.append(host.lower())
                    estimated_hosts += 1
        except ValueError as exc:
            return jsonify({"status": "error", "message": str(exc)}), 400

    if not new_scope.has_scope():
        return jsonify({"status": "error", "message": "No valid targets were supplied"}), 400
    scope_mgr = new_scope

    if sources_mode == "all":
        sources = ["masscan", "tcp", "onvif", "ssdp"]
        if new_scope.domains or new_scope.asns:
            sources = ["fofa", "zoomeye", "shodan", "crtsh", "dns", *sources]
    elif sources_mode == "passive":
        sources = ["fofa", "zoomeye", "shodan", "crtsh", "dns", "onvif", "ssdp"]
    elif sources_mode == "internet":
        sources = ["fofa", "zoomeye", "shodan", "crtsh", "dns"]
    elif sources_mode == "local":
        sources = ["onvif", "ssdp", "masscan", "tcp"]
    else:
        sources = [sources_mode]

    uses_masscan = "masscan" in sources
    high_intensity = mode in {ScanMode.WAR.value, ScanMode.NUKE.value}
    mass_sweep = uses_masscan and estimated_hosts > 256
    needs_large_confirmation = has_asn_target or has_large_cidr or estimated_hosts >= 1000 or mass_sweep or high_intensity
    if needs_large_confirmation and not confirm_large:
        reasons = []
        if has_asn_target:
            reasons.append("ASN target")
        if has_large_cidr or estimated_hosts >= 1000:
            reasons.append(f"about {estimated_hosts} IPs")
        if mass_sweep:
            reasons.append("Masscan sweep")
        if high_intensity:
            reasons.append(f"{mode} mode")
        return jsonify({
            "status": "confirmation_required",
            "message": "Large scan confirmation is required for " + ", ".join(reasons),
        }), 400

    check_creds = options in {"default_audit", "no_thumbs", "full"}
    grab_thumbs = options == "full"

    if options == "discover":
        phases = [
            DiscoveryOrchestrator.PHASE_DISCOVER,
            DiscoveryOrchestrator.PHASE_IDENTIFY,
        ]
    else:
        phases = [
            DiscoveryOrchestrator.PHASE_DISCOVER,
            DiscoveryOrchestrator.PHASE_IDENTIFY,
            DiscoveryOrchestrator.PHASE_VERIFY,
        ]

    active_orchestrator = DiscoveryOrchestrator(
        db=db, scope_mgr=scope_mgr, proxy_mgr=proxy_mgr,
        targets=targets, sources=sources, mode=mode,
        check_creds=check_creds, grab_thumbs=grab_thumbs,
        custom_ports=custom_ports,
    )

    orch = active_orchestrator  # Capture in closure to avoid race

    def run_pipeline():
        try:
            results = orch.run(phases)
            db.add_scan({
                "target": target,
                "engine": ",".join(sources),
                "mode": mode,
                "start_time": datetime.now().isoformat(),
                "end_time": datetime.now().isoformat(),
                "assets_found": len(results),
                "vulnerable": sum(1 for r in results if r.get("status") == "vulnerable"),
            })
        finally:
            # Clear reference so old scans don't leak memory/state
            global active_orchestrator
            if active_orchestrator is orch:
                active_orchestrator = None

    thread = threading.Thread(target=run_pipeline, daemon=True)
    thread.start()
    return jsonify({"status": "started"})


@app.route("/api/scan/stop", methods=["POST"])
def stop_scan():
    if active_orchestrator:
        active_orchestrator.stop()
    return jsonify({"status": "stopped"})


@app.route("/api/scan/status")
def scan_status():
    if active_orchestrator:
        return jsonify({
            "running": active_orchestrator.running,
            "progress": active_orchestrator.progress[-60:],
            "phase": active_orchestrator.phase,
            "stats": active_orchestrator.stats,
        })
    return jsonify({"running": False, "progress": [], "stats": {}})


@app.route("/api/assets")
def get_assets():
    filters = {}
    f = request.args.get("filter")
    if f == "no_pass":
        filters["access_level"] = "full"
    elif f == "default":
        filters["access_level"] = "default"
    elif f == "crack":
        filters["access_level"] = "needs_cracking"
    elif f == "vuln":
        filters["status"] = "vulnerable"
    search = request.args.get("search")
    if search:
        filters["search"] = search
    return jsonify(db.get_assets(filters))


@app.route("/api/asset/<int:asset_id>")
def get_asset(asset_id):
    asset = db.get_asset(asset_id)
    if asset:
        return jsonify(asset)
    return jsonify({"error": "Not found"}), 404


@app.route("/api/asset/<int:asset_id>/services")
def get_services(asset_id):
    return jsonify(db.get_services(asset_id))


@app.route("/api/asset/<int:asset_id>/findings")
def get_findings(asset_id):
    if not db.get_asset(asset_id):
        return jsonify({"error": "Asset not found"}), 404
    return jsonify(db.get_findings(asset_id))


@app.route("/api/asset/<int:asset_id>/assess", methods=["POST"])
def assess_asset(asset_id):
    asset = db.get_asset(asset_id)
    if not asset:
        return jsonify({"status": "error", "message": "Asset not found"}), 404
    if not asset.get("vendor") or str(asset.get("vendor")).lower() == "unknown":
        return jsonify({
            "status": "error",
            "message": "The camera vendor must be identified before CVE assessment",
        }), 400

    job_id = db.add_job(asset_id, "defensive_cve_assessment")

    def run_assessment():
        messages: List[str] = []

        def report(message: str) -> None:
            messages.append(message)
            logger.info("Asset %s assessment: %s", asset_id, message)
            db.update_job(job_id, result=json.dumps({"progress": messages[-12:]}))

        db.update_job(job_id, status="running", started=datetime.now().isoformat())
        try:
            findings = VulnerabilityIntelligence.assess(
                asset, db.get_services(asset_id), progress=report,
            )
            db.replace_findings(asset_id, findings)
            db.update_job(
                job_id,
                status="completed",
                finished=datetime.now().isoformat(),
                result=json.dumps({
                    "finding_count": len(findings),
                    "known_exploited": sum(1 for finding in findings if finding.get("known_exploited")),
                    "message": "Potential matches require model/firmware verification; no exploit was executed.",
                    "progress": messages[-12:],
                }),
            )
        except Exception as exc:
            db.update_job(
                job_id,
                status="error",
                finished=datetime.now().isoformat(),
                result=json.dumps({"message": str(exc), "progress": messages[-12:]}),
            )

    threading.Thread(target=run_assessment, daemon=True).start()
    return jsonify({"status": "started", "job_id": job_id})


@app.route("/api/asset/<int:asset_id>/report")
def asset_report(asset_id):
    asset = db.get_asset(asset_id)
    if not asset:
        return jsonify({"error": "Asset not found"}), 404
    report = {
        "generated_at": datetime.now().isoformat(),
        "assessment_type": "defensive vulnerability correlation",
        "asset": asset,
        "services": db.get_services(asset_id),
        "findings": db.get_findings(asset_id),
        "interpretation": (
            "A CVE match is a remediation lead, not proof of exploitation. Confirm the exact model and firmware "
            "against the linked vendor/NVD advisory before changing production systems."
        ),
        "exploit_execution": "not performed",
    }
    response = app.response_class(
        response=json.dumps(report, indent=2, default=str),
        status=200,
        mimetype="application/json",
    )
    if request.args.get("download") == "1":
        response.headers["Content-Disposition"] = f'attachment; filename="oculux_asset_{asset_id}_report.json"'
    return response


@app.route("/api/stats")
def get_stats():
    return jsonify(db.get_stats())


@app.route("/api/vulns")
def get_vulns():
    vendor = request.args.get("vendor")
    return jsonify(db.get_vulns(vendor))


@app.route("/api/scope", methods=["GET", "POST"])
def scope_api():
    if request.method == "POST":
        data = request.json or {}
        stype = data.get("type")
        value = data.get("value", "")
        if stype == "cidr":
            scope_mgr.add_cidr(value)
        elif stype == "domain":
            scope_mgr.add_domain(value)
        elif stype == "asn":
            scope_mgr.add_asn(value)
        elif stype == "range":
            try:
                start = ipaddress.ip_address(data.get("start"))
                end = ipaddress.ip_address(data.get("end"))
                count = 0
                while start <= end and count < 65536:
                    scope_mgr.add_cidr(f"{start}/32")
                    start += 1
                    count += 1
            except ValueError:
                pass
        return jsonify({"status": "added"})
    return jsonify(scope_mgr.to_dict())


@app.route("/api/blocklist", methods=["GET", "POST"])
def blocklist_api():
    if request.method == "POST":
        data = request.json or {}
        db.add_to_blocklist(data.get("ip"), data.get("reason", "opt-out"))
        return jsonify({"status": "blocked"})
    return jsonify(db.get_blocklist())


@app.route("/api/proxy", methods=["POST", "DELETE"])
def proxy_api():
    if request.method == "POST":
        data = request.json or {}
        proxy_mgr.configure(
            data.get("type"),
            data.get("host"),
            int(data.get("port", 0)),
            data.get("user"),
            data.get("pass"),
        )
        return jsonify({"status": "saved"})
    proxy_mgr.clear()
    return jsonify({"status": "cleared"})


@app.route("/api/tools")
def get_tools():
    tools = {
        "masscan": {"available": find_tool("masscan") is not None, "path": find_tool("masscan")},
        "nmap": {"available": find_tool("nmap") is not None, "path": find_tool("nmap")},
        "hydra": {"available": find_tool("hydra") is not None, "path": find_tool("hydra")},
        "searchsploit": {"available": find_tool("searchsploit") is not None, "path": find_tool("searchsploit")},
        "msfconsole": {"available": find_tool("msfconsole") is not None, "path": find_tool("msfconsole")},
        "ffmpeg": {"available": find_tool("ffmpeg") is not None, "path": find_tool("ffmpeg")},
        "tshark": {"available": find_tool("tshark") is not None, "path": find_tool("tshark")},
    }
    return jsonify(tools)


@app.route("/api/crack", methods=["POST"])
def start_crack():
    data = request.json or {}
    asset_id = data.get("asset_id")
    protocol = data.get("protocol", "http")
    threads = data.get("threads", 4)

    asset = db.get_asset(asset_id)
    if not asset:
        return jsonify({"status": "error", "message": "Asset not found"})

    job_id = db.add_job(asset_id, "hydra")

    def run_crack():
        db.update_job(job_id, status="running", started=datetime.now().isoformat())
        svcs = db.get_services(asset_id)
        port = svcs[0]["port"] if svcs else 80
        paths = json.loads(svcs[0].get("paths", "[]")) if svcs else []
        result = HydraCracker.crack(
            asset["primary_ip"], port, protocol, paths,
            threads=threads,
        )
        db.update_job(
            job_id,
            status=result["status"],
            finished=datetime.now().isoformat(),
            result=json.dumps(result),
        )
        if result["status"] == "cracked":
            db.upsert_asset({
                "ip": asset["primary_ip"],
                "access_level": "cracked",
                "auth_user": result.get("user"),
                "auth_pass": result.get("password"),
                "has_password": 1,
                "status": "vulnerable",
            }, scope_mgr)

    threading.Thread(target=run_crack, daemon=True).start()
    return jsonify({"status": "started", "job_id": job_id})


@app.route("/api/asset/<int:asset_id>/test-defaults", methods=["POST"])
def test_default_passwords(asset_id):
    asset = db.get_asset(asset_id)
    if not asset:
        return jsonify({"status": "error", "message": "Asset not found"}), 404

    job_id = db.add_job(asset_id, "default_password_audit")

    def run_audit():
        messages: List[str] = []

        def report(message: str) -> None:
            messages.append(message)
            logger.info("Asset %s default-password audit: %s", asset_id, message)
            db.update_job(job_id, result=json.dumps({"progress": messages[-12:]}))

        db.update_job(job_id, status="running", started=datetime.now().isoformat())
        try:
            result = DefaultCredentialAuditor.audit(asset, db.get_services(asset_id), progress=report)
            if result.get("status") in {"no_password_found", "default_credentials_found"}:
                db.upsert_asset({
                    "ip": asset["primary_ip"],
                    "port": result.get("port") or asset.get("primary_port"),
                    "vendor": asset.get("vendor"),
                    "model": asset.get("model"),
                    "firmware": asset.get("firmware"),
                    "access_level": result.get("access_level"),
                    "has_password": result.get("has_password"),
                    "auth_user": result.get("auth_user", ""),
                    "auth_pass": result.get("auth_pass", ""),
                    "status": "vulnerable",
                }, ScopeManager())
            elif result.get("status") == "no_default_credentials_found":
                db.upsert_asset({
                    "ip": asset["primary_ip"],
                    "vendor": asset.get("vendor"),
                    "model": asset.get("model"),
                    "firmware": asset.get("firmware"),
                    "access_level": "needs_cracking",
                    "has_password": 1,
                }, ScopeManager())

            safe_result = DefaultCredentialAuditor.sanitized(result)
            safe_result["progress"] = messages[-12:]
            db.update_job(
                job_id,
                status="completed",
                finished=datetime.now().isoformat(),
                result=json.dumps(safe_result),
            )
        except Exception as exc:
            db.update_job(
                job_id,
                status="error",
                finished=datetime.now().isoformat(),
                result=json.dumps({"message": str(exc), "progress": messages[-12:]}),
            )

    threading.Thread(target=run_audit, daemon=True).start()
    return jsonify({"status": "started", "job_id": job_id})


@app.route("/api/msf/run", methods=["POST"])
def run_msf():
    if os.getenv("OCULUX_ENABLE_EXPLOIT_EXECUTION") != "1":
        return jsonify({
            "status": "disabled",
            "message": (
                "Exploit execution is disabled by default. Use the defensive asset assessment to correlate "
                "Metasploit modules without running them."
            ),
        }), 403
    data = request.json or {}
    if data.get("confirmed") is not True:
        return jsonify({
            "status": "error",
            "message": "Manual exploit execution requires explicit single-asset confirmation",
        }), 400
    module = str(data.get("module") or "")
    if not re.fullmatch(r"(?:exploit|auxiliary)/[A-Za-z0-9_./-]+", module):
        return jsonify({"status": "error", "message": "Invalid Metasploit module path"}), 400
    try:
        rport = int(data.get("rport", 80))
    except (TypeError, ValueError):
        return jsonify({"status": "error", "message": "Invalid port"}), 400
    if not 1 <= rport <= 65535:
        return jsonify({"status": "error", "message": "Port must be between 1 and 65535"}), 400
    asset_id = data.get("asset_id")

    asset = db.get_asset(asset_id)
    if not asset:
        return jsonify({"status": "error", "message": "Asset not found"}), 404

    job_id = db.add_job(asset_id, "msf")

    def run_exploit():
        db.update_job(job_id, status="running", started=datetime.now().isoformat())
        result = MetasploitRunner.run_exploit(
            module, asset["primary_ip"], rport
        )
        db.update_job(
            job_id,
            status=result["status"],
            finished=datetime.now().isoformat(),
            result=json.dumps(result),
        )

    threading.Thread(target=run_exploit, daemon=True).start()
    return jsonify({"status": "started", "job_id": job_id})


@app.route("/api/jobs")
def get_jobs():
    return jsonify(db.get_jobs())


@app.route("/api/decay", methods=["POST"])
def compute_decay():
    db.compute_decay()
    return jsonify({"status": "computed"})


@app.route("/api/export/csv")
def export_csv():
    assets = db.get_assets({})
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "ID", "IP", "Port", "Vendor", "Model", "Firmware", "Type",
        "Confidence", "Classification", "Access Level", "Status",
        "Country", "City", "Latitude", "Longitude", "First Seen",
        "Last Seen", "Discovery Source"
    ])
    for a in assets:
        writer.writerow([
            a.get("id"), a.get("primary_ip"), a.get("primary_port"),
            a.get("vendor"), a.get("model"), a.get("firmware"),
            a.get("camera_type"), a.get("confidence"),
            a.get("classification"), a.get("access_level"),
            a.get("status"), a.get("country"), a.get("city"),
            a.get("latitude"), a.get("longitude"), a.get("first_seen"),
            a.get("last_seen"), a.get("discovery_source")
        ])
    output.seek(0)
    return send_file(
        io.BytesIO(output.getvalue().encode()),
        mimetype="text/csv",
        as_attachment=True,
        download_name=f"oculux_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    )


@app.route("/api/export/db")
def export_db():
    return send_file(
        db.path,
        mimetype="application/x-sqlite3",
        as_attachment=True,
        download_name="oculux_backup.db"
    )


@app.route("/api/db/clear", methods=["POST"])
def clear_db():
    db.clear_all()
    return jsonify({"status": "cleared"})


@app.route("/thumbnails/<path:filename>")
def serve_thumbnail(filename):
    thumb_dir = Path("thumbnails").resolve()
    if not thumb_dir.exists():
        return jsonify({"error": "Not found"}), 404

    # Safe join prevents path traversal
    safe_path = safe_join(str(thumb_dir), filename)
    if safe_path is None:
        return jsonify({"error": "Invalid path"}), 400

    file_path = Path(safe_path).resolve()
    # Ensure the resolved path is still inside thumb_dir
    if not str(file_path).startswith(str(thumb_dir)):
        return jsonify({"error": "Access denied"}), 403

    if file_path.exists() and file_path.is_file():
        return send_file(file_path, mimetype="image/jpeg")
    return jsonify({"error": "Not found"}), 404


# ═══════════════════════════════════════════════════════════════
# GLOBALS & MAIN ENTRY
# ═══════════════════════════════════════════════════════════════

db = Database()
scope_mgr = ScopeManager()
proxy_mgr = ProxyManager()
rate_limiter = RateLimiter()

def run_cli(args: argparse.Namespace) -> int:
    """CLI mode: run a scan headlessly and output results."""
    targets = [t.strip() for t in args.target.split(",") if t.strip()]
    if not targets:
        print("[!] No targets specified")
        return 1

    new_scope = ScopeManager()
    scan_targets: List[str] = []
    custom_ports: Set[int] = set()
    for part in targets:
        try:
            host, custom_port = parse_target_spec(part)
            if custom_port:
                custom_ports.add(custom_port)
            if host.upper().startswith("AS"):
                new_scope.add_asn(host)
            elif "/" in host:
                net = ipaddress.ip_network(host, strict=False)
                new_scope.add_cidr(str(net))
                scan_targets.append(str(net))
            else:
                try:
                    ipaddress.ip_address(host)
                    new_scope.add_cidr(f"{host}/32")
                    scan_targets.append(host)
                except ValueError:
                    new_scope.add_domain(host.lower())
                    scan_targets.append(host.lower())
        except ValueError as exc:
            print(f"[!] Invalid target {part}: {exc}")
            return 1

    sources = [s.strip() for s in args.sources.split(",") if s.strip()]
    if args.no_passive:
        sources = [s for s in sources if s not in ("fofa", "zoomeye", "shodan", "crtsh", "dns")]
    if args.local_only:
        sources = ["onvif", "ssdp", "masscan", "tcp"]

    orch = DiscoveryOrchestrator(
        db=db, scope_mgr=new_scope, proxy_mgr=proxy_mgr,
        targets=scan_targets, sources=sources, mode=args.mode,
        check_creds=not args.no_creds, grab_thumbs=not args.no_thumbs,
        custom_ports=custom_ports,
    )

    def cli_progress(message: str) -> None:
        print(f"  {message}")

    # Override log to print to console
    orch.log = lambda message, level="info": print(
        f"[{datetime.now().strftime('%H:%M:%S')}] {'✓' if level == 'ok' else '✗' if level == 'err' else '⚠' if level == 'warn' else '●'} {message}"
    )

    phases = [DiscoveryOrchestrator.PHASE_DISCOVER, DiscoveryOrchestrator.PHASE_IDENTIFY]
    if not args.no_creds:
        phases.append(DiscoveryOrchestrator.PHASE_VERIFY)

    print(f"\n╔══════════════════════════════════════════════════════════════╗")
    print(f"║  Oculux v7.5 CLI — Defensive Camera Verification              ║")
    print(f"║  Mode: {args.mode:<10}  Targets: {len(targets)}  Sources: {len(sources)}  ║")
    print(f"╚══════════════════════════════════════════════════════════════╝\n")

    start_time = time.time()
    results = orch.run(phases)
    elapsed = time.time() - start_time

    # Print summary
    stats = db.get_stats()
    print(f"\n{'═' * 60}")
    print(f"  SCAN COMPLETE — {elapsed:.1f}s")
    print(f"{'═' * 60}")
    print(f"  Total assets:     {stats['total_assets']}")
    print(f"  No password:      {stats['no_password']}")
    print(f"  Default creds:    {stats['default_creds']}")
    print(f"  Needs cracking:   {stats['needs_cracking']}")
    print(f"  Vulnerable:       {stats['vulnerable']}")
    print(f"  Unique vendors:   {stats['unique_vendors']}")
    print(f"{'═' * 60}")

    # Print asset table
    if results:
        print(f"\n  {'IP':<18} {'PORT':<6} {'VENDOR':<12} {'MODEL':<20} {'CONF':<6} {'ACCESS':<12} {'SOURCE'}")
        print(f"  {'-' * 80}")
        for r in results[:50]:
            ip = r.get("ip", "")
            port = r.get("port", 0)
            vendor = r.get("vendor", "?")[:12]
            model = (r.get("model") or "-")[:20]
            conf = f"{r.get('confidence', 0)}%"
            access = r.get("access_level", "unknown")[:12]
            src = r.get("discovery_source", "?")[:12]
            print(f"  {ip:<18} {port:<6} {vendor:<12} {model:<20} {conf:<6} {access:<12} {src}")
        if len(results) > 50:
            print(f"  ... and {len(results) - 50} more")

    # Generate HTML report
    if args.report:
        assets = db.get_assets({})
        findings_map = {}
        for a in assets:
            findings_map[a["id"]] = db.get_findings(a["id"])
        html = HTMLReportGenerator.generate(assets, stats, findings_map)
        report_path = args.report
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(html)
        print(f"\n  📄 HTML report saved to: {report_path}")

    # Telegram notification
    notifier = TelegramNotifier()
    if notifier.enabled:
        notifier.notify_scan_complete(stats)
        print("  📱 Telegram notification sent")

    # Geo enrichment
    if args.geo:
        print("\n  🌍 Enriching with geolocation...")
        for a in db.get_assets({}):
            if not a.get("country") and a.get("primary_ip"):
                geo = GeoEnricher.enrich(a["primary_ip"])
                if geo:
                    db.upsert_asset({
                        "ip": a["primary_ip"],
                        "country": geo.get("country"),
                        "city": geo.get("city"),
                        "latitude": geo.get("latitude"),
                        "longitude": geo.get("longitude"),
                        "org": geo.get("org"),
                        "asn": geo.get("asn"),
                    }, ScopeManager())
        print("  ✓ Geolocation enrichment complete")

    return 0


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Oculux v7.5 Defensive Camera Verification Framework",
        epilog="Examples:\n"
               "  python Oculux.py --cli --target 192.168.1.0/24 --mode medium\n"
               "  python Oculux.py --cli --target 10.0.0.0/8 --mode nuke --sources masscan,tcp\n"
               "  python Oculux.py --cli --target 192.168.1.10:8554 --no-creds\n"
               "  python Oculux.py --cli --target 1.2.3.4 --report report.html --geo\n"
               "  python Oculux.py --host 0.0.0.0 --port 5000",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--host", default="0.0.0.0", help="Bind address (dashboard mode)")
    parser.add_argument("--port", type=int, default=5000, help="Bind port (dashboard mode)")
    parser.add_argument("--debug", action="store_true", help="Debug mode (dashboard mode)")
    parser.add_argument("--mode", choices=[m.value for m in ScanMode], default="medium",
                       help="Scan mode")
    parser.add_argument("--cli", action="store_true", help="Run in CLI mode (headless)")
    parser.add_argument("--target", default="", help="Target: CIDR, IP, IP:PORT, domain, or comma-separated list")
    parser.add_argument("--sources", default="masscan,tcp,onvif,ssdp",
                       help="Comma-separated discovery sources: fofa,zoomeye,shodan,crtsh,dns,masscan,tcp,onvif,ssdp")
    parser.add_argument("--no-creds", action="store_true", help="Skip credential checking")
    parser.add_argument("--no-thumbs", action="store_true", help="Skip thumbnail capture")
    parser.add_argument("--no-passive", action="store_true", help="Skip passive internet sources (FOFA, ZoomEye, etc.)")
    parser.add_argument("--local-only", action="store_true", help="Only use local discovery (ONVIF, SSDP, masscan, TCP)")
    parser.add_argument("--report", default="", help="Generate HTML report to this path")
    parser.add_argument("--geo", action="store_true", help="Enrich results with IP geolocation")
    args = parser.parse_args()

    if args.cli:
        if not args.target:
            parser.error("--target is required in CLI mode")
        sys.exit(run_cli(args))

    print(f"""
    ╔════════════════════════════════════════════════════════════════════════╗
    ║  Oculux v7.5 - Defensive Camera Verification                            ║
    ║  Mode: {args.mode:<10}                                                  ║
    ║  Dashboard: http://{args.host}:{args.port:<5}                           ║
    ║  CLI: python Oculux.py --cli --target <TARGET>                          ║
    ╚════════════════════════════════════════════════════════════════════════╝
    """)

    try:
        app.run(host=args.host, port=args.port, debug=args.debug, threaded=True)
    except KeyboardInterrupt:
        print("\n[!] Shutting down...")
        db.close()
        sys.exit(0)
