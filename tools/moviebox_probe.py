import json
import os
import base64
import hashlib
import hmac
import json
import os
import time
from urllib.parse import parse_qs, urlparse

import requests

MAIN = os.getenv("MOVIEBOX_BASE", "https://api.inmoviebox.com")

# The API can be sensitive to the client identity in x-client-info and UA.
# Default to the APK identity the user reported (com.community.oneroom).
PACKAGE_NAME = os.getenv("MOVIEBOX_PACKAGE", "com.community.oneroom")
VERSION_CODE = int(os.getenv("MOVIEBOX_VERSION_CODE", "50020042"))
VERSION_NAME = os.getenv("MOVIEBOX_VERSION_NAME", "3.0.03.0529.03")

UA = os.getenv(
    "MOVIEBOX_UA",
    f"{PACKAGE_NAME}/{VERSION_CODE} (Linux; U; Android 16; en_IN; sdk_gphone64_x86_64; Build/BP22.250325.006; Cronet/133.0.6876.3)",
)

DEFAULT_XINFO_OBJ = {
    "package_name": PACKAGE_NAME,
    "version_name": VERSION_NAME,
    "version_code": VERSION_CODE,
    "os": "android",
    "os_version": "16",
    "device_id": "da2b99c821e6ea023e4be55b54d5f7d8",
    "install_store": "ps",
    "gaid": "d7578036d13336cc",
    "brand": "google",
    "model": "sdk_gphone64_x86_64",
    "system_language": "en",
    "net": "NETWORK_WIFI",
    "region": "IN",
    "timezone": "Asia/Calcutta",
    "sp_code": "",
}

XINFO = os.getenv("MOVIEBOX_XINFO", json.dumps(DEFAULT_XINFO_OBJ, separators=(",", ":")))

CONFUSABLES = str.maketrans(
    {
        "Ø": "0",
        "О": "O",  # Cyrillic O
        "о": "o",
        "Е": "E",  # Cyrillic E
        "е": "e",
        "В": "B",  # Cyrillic Ve
        "Х": "X",  # Cyrillic Ha
        "х": "x",
        "Т": "T",  # Cyrillic Te
        "т": "t",
        "п": "n",  # Cyrillic pe; sometimes pasted where 'n' intended
        "П": "N",
    }
)


def normalize_secret(s: str) -> str:
    return (s or "").strip().translate(CONFUSABLES)


def b64decode_any(s: str) -> bytes:
    s = normalize_secret(s)
    if not s:
        return b""
    # accept URL-safe base64 and missing padding
    s = s.replace("-", "+").replace("_", "/")
    pad = (-len(s)) % 4
    if pad:
        s += "=" * pad
    return base64.b64decode(s)


def md5_hex(v: bytes) -> str:
    return hashlib.md5(v).hexdigest()


def x_client_token() -> str:
    ts = str(int(time.time() * 1000))
    return f"{ts},{md5_hex(ts[::-1].encode())}"


def canonical(method: str, accept: str, ctype: str, url: str, body: str | None, ts_ms: int) -> str:
    p = urlparse(url)
    q = parse_qs(p.query, keep_blank_values=True)
    query = "&".join(f"{k}={v}" for k in sorted(q) for v in q[k])
    canon_path = f"{p.path}?{query}" if query else p.path

    body_hash = ""
    body_len = ""
    if body is not None:
        b = body.encode()
        body_hash = md5_hex(b[:102400])
        body_len = str(len(b))

    return (
        f"{method.upper()}\n"
        f"{accept or ''}\n"
        f"{ctype or ''}\n"
        f"{body_len}\n"
        f"{ts_ms}\n"
        f"{body_hash}\n"
        f"{canon_path}"
    )


def signature(secret_key_bytes: bytes, method: str, accept: str, ctype: str, url: str, body: str | None = None) -> str:
    ts_ms = int(time.time() * 1000)
    can = canonical(method, accept, ctype, url, body, ts_ms)
    sig_b64 = base64.b64encode(hmac.new(secret_key_bytes, can.encode(), hashlib.md5).digest()).decode()
    return f"{ts_ms}|2|{sig_b64}"


def headers(
    secret_key_bytes: bytes,
    url: str,
    method: str = "GET",
    body: str | None = None,
    accept: str = "application/json",
    ctype: str = "application/json",
) -> dict:
    return {
        "user-agent": UA,
        "accept": accept,
        "content-type": ctype,
        "connection": "keep-alive",
        "x-client-token": x_client_token(),
        "x-tr-signature": signature(secret_key_bytes, method, accept, ctype, url, body),
        "x-client-info": XINFO,
        "x-client-status": "0",
        "x-play-mode": "2",
    }


def list_subject_ids(secret_key_bytes: bytes) -> list[str]:
    url = f"{MAIN}/wefeed-mobile-bff/subject-api/list"
    body = json.dumps({"page": 1, "perPage": 12, "rate": ["0", "10"], "genre": "All"}, separators=(",", ":"))
    r = requests.post(
        url,
        headers=headers(secret_key_bytes, url, "POST", body, "application/json", "application/json; charset=utf-8"),
        data=body,
        timeout=20,
    )
    print("LIST_STATUS", r.status_code)
    print("LIST_HEAD", r.text[:220].replace("\n", " "))
    if not r.ok:
        return []
    try:
        j = r.json()
        items = (((j.get("data") or {}).get("items")) or [])
        out: list[str] = []
        for it in items:
            sid = it.get("subjectId") or it.get("id")
            if sid:
                out.append(str(sid))
        print("LIST_ITEMS", len(items))
        return out
    except Exception:
        return []


def get_subject_detail(secret_key_bytes: bytes, subject_id: str) -> dict:
    url = f"{MAIN}/wefeed-mobile-bff/subject-api/get?subjectId={subject_id}"
    r = requests.get(url, headers=headers(secret_key_bytes, url, "GET"), timeout=20)
    if not r.ok:
        return {"status": r.status_code}
    try:
        j = r.json()
        data = j.get("data") or {}
        return {
            "status": r.status_code,
            "subjectType": data.get("subjectType"),
            "hasResource": data.get("hasResource"),
            "title": data.get("title"),
            "dubs": data.get("dubs") or [],
            "resourceDetectors": data.get("resourceDetectors") or [],
        }
    except Exception:
        return {"status": r.status_code}


def first_download_url_from_detail(detail: dict) -> str | None:
    dets = detail.get("resourceDetectors")
    if not isinstance(dets, list) or not dets:
        return None
    first = dets[0]
    if not isinstance(first, dict):
        return None
    return first.get("downloadUrl") or first.get("resourceLink")


def try_play_info(secret_key_bytes: bytes, subject_id: str) -> bool:
    combos = [(0, 0), (0, 1), (1, 0), (1, 1)]
    for se, ep in combos:
        url = f"{MAIN}/wefeed-mobile-bff/subject-api/play-info?subjectId={subject_id}&se={se}&ep={ep}"
        r = requests.get(url, headers=headers(secret_key_bytes, url, "GET"), timeout=20)
        print("PLAY_STATUS", subject_id, f"S{se}E{ep}", r.status_code)
        print("PLAY_HEAD", subject_id, f"S{se}E{ep}", r.text[:220].replace("\n", " "))
        if not r.ok:
            continue
        try:
            j = r.json()
            streams = (((j.get("data") or {}).get("streams")) or [])
            print("PLAY_STREAMS", subject_id, f"S{se}E{ep}", len(streams))
            if streams:
                return True
        except Exception:
            pass

    # Some clients omit se/ep (especially for movies)
    url = f"{MAIN}/wefeed-mobile-bff/subject-api/play-info?subjectId={subject_id}"
    r = requests.get(url, headers=headers(secret_key_bytes, url, "GET"), timeout=20)
    print("PLAY_STATUS", subject_id, "NO_SE_EP", r.status_code)
    print("PLAY_HEAD", subject_id, "NO_SE_EP", r.text[:220].replace("\n", " "))
    if not r.ok:
        return False
    try:
        j = r.json()
        streams = (((j.get("data") or {}).get("streams")) or [])
        print("PLAY_STREAMS", subject_id, "NO_SE_EP", len(streams))
        return bool(streams)
    except Exception:
        return False


def probe_with_secret(label: str, secret_b64: str) -> None:
    print("\n===", label, "===")
    secret_b64_norm = normalize_secret(secret_b64)
    print("secret_chars:", len(secret_b64), "normalized_chars:", len(secret_b64_norm))

    try:
        key_bytes = b64decode_any(secret_b64)
    except Exception as e:
        print("SECRET_DECODE_ERROR", e)
        return

    print("key_bytes_len:", len(key_bytes))

    sids = list_subject_ids(key_bytes)
    if not sids:
        print("NO_SUBJECT_IDS")
        return

    for sid in sids[:8]:
        detail = get_subject_detail(key_bytes, sid)
        dl = first_download_url_from_detail(detail)
        print(
            "DETAIL",
            sid,
            "status",
            detail.get("status"),
            "subjectType",
            detail.get("subjectType"),
            "hasResource",
            detail.get("hasResource"),
            "title",
            (detail.get("title") or "")[:50],
            "hasDownloadUrl",
            bool(dl),
        )

        if dl:
            print("DOWNLOAD_URL", dl)
            try:
                h = requests.head(dl, allow_redirects=True, timeout=20)
                print("DOWNLOAD_HEAD", h.status_code)
            except Exception as e:
                print("DOWNLOAD_HEAD_ERR", e)

            # This is enough to conclude the extension should be able to emit a playable link.
            print("SUCCESS_SUBJECT", sid)
            return

    print("NO_STREAMS_FOUND")


def main() -> None:
    default_secret = os.getenv("MOVIEBOX_SECRET_KEY_DEFAULT", "")
    alt_secret = os.getenv("MOVIEBOX_SECRET_KEY_ALT", "")

    if not default_secret and not alt_secret:
        raise SystemExit("Missing secrets: set MOVIEBOX_SECRET_KEY_DEFAULT and/or MOVIEBOX_SECRET_KEY_ALT in env.")

    if default_secret:
        probe_with_secret("DEFAULT", default_secret)
    if alt_secret:
        probe_with_secret("ALT", alt_secret)


if __name__ == "__main__":
    main()
