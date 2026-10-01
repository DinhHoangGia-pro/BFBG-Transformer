"""
fetch_trickbot_sample.py
========================
Tai mot lo nho mau PE theo signature tu MalwareBazaar (mac dinh TrickBot)
vao data/raw/malicious/<sha256> (khong duoi file). Mau CHI duoc ghi ra dia
duoi dang bytes - KHONG BAO GIO execute; file ghi ra o che do chi-doc,
khong co quyen thuc thi.

  - API key doc tu bien MALWAREBAZAAR_API_KEY trong .env o goc repo
    (.env da nam trong .gitignore). Key khong bao gio duoc in ra.
  - Zip cua MalwareBazaar ma hoa AES, mat khau "infected" -> giai nen
    TRONG BO NHO bang pyzipper, khong ghi file zip ra dia.
  - Chi giu mau la PE (2 byte dau "MZ") va sha256 khop voi hash da yeu cau;
    moi mau bi bo deu duoc liet ke kem ly do.
  - Metadata (signature, file_type, first_seen, tags...) ghi them vao
    data/raw/fetch_manifest.jsonl de truy nguon.
  - KHONG tai report VirusTotal.

Chay:  python scripts/fetch_trickbot_sample.py [--count 25] [--signature TrickBot]
"""

import argparse
import datetime
import hashlib
import io
import json
import os
import sys
import time

import pyzipper
import requests

from src.utils.path_resolver import REPO_ROOT, load_config, resolve

API_URL = 'https://mb-api.abuse.ch/api/v1/'
ZIP_PASSWORD = b'infected'
PE_FILE_TYPES = {'exe', 'dll'}


def load_api_key(env_path):
    if not os.path.exists(env_path):
        sys.exit(f"Khong tim thay {env_path} - them dong MALWAREBAZAAR_API_KEY=<key> vao .env o goc repo.")
    with open(env_path) as f:
        for line in f:
            line = line.strip()
            if line.startswith('#') or '=' not in line:
                continue
            name, value = line.split('=', 1)
            if name.strip() == 'MALWAREBAZAAR_API_KEY':
                value = value.strip().strip('"').strip("'")
                if value:
                    return value
    sys.exit(f"{env_path} khong co gia tri MALWAREBAZAAR_API_KEY.")


def api_query(session, data, timeout=60):
    resp = session.post(API_URL, data=data, timeout=timeout)
    resp.raise_for_status()
    return resp


def list_signature(session, signature, limit):
    body = api_query(session, {'query': 'get_siginfo', 'signature': signature, 'limit': limit}).json()
    if body.get('query_status') != 'ok':
        sys.exit(f"MalwareBazaar get_siginfo('{signature}') -> query_status={body.get('query_status')!r} "
                 f"(kiem tra ten signature, phan biet hoa/thuong, vd 'TrickBot').")
    return body.get('data') or []


def download_sample(session, sha256):
    """Bytes cua mau (da giai nen), hoac raise ValueError kem ly do."""
    resp = api_query(session, {'query': 'get_file', 'sha256_hash': sha256}, timeout=120)
    content = resp.content
    if not content.startswith(b'PK'):
        try:
            status = resp.json().get('query_status')
        except ValueError:
            status = content[:80]
        raise ValueError(f"API khong tra zip: {status!r}")
    with pyzipper.AESZipFile(io.BytesIO(content)) as zf:
        zf.setpassword(ZIP_PASSWORD)
        names = zf.namelist()
        if len(names) != 1:
            raise ValueError(f"zip co {len(names)} file, mong doi 1: {names[:5]}")
        return zf.read(names[0])


def save_sample(data, sha256, out_dir):
    """Kiem tra roi ghi mau ra out_dir/<sha256>, che do 0o444 (khong quyen thuc thi)."""
    actual = hashlib.sha256(data).hexdigest()
    if actual != sha256:
        raise ValueError(f"sha256 sau giai nen ({actual}) khac hash yeu cau")
    if data[:2] != b'MZ':
        raise ValueError(f"khong phai PE (2 byte dau = {data[:2]!r})")
    path = os.path.join(out_dir, sha256)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o444)
    with os.fdopen(fd, 'wb') as f:
        f.write(data)
    return path


def main():
    parser = argparse.ArgumentParser(description="Tai lo nho mau PE theo signature tu MalwareBazaar")
    parser.add_argument('--signature', default='TrickBot', help="Ten signature tren MalwareBazaar (phan biet hoa/thuong)")
    parser.add_argument('--count', type=int, default=25, help="So mau PE can tai (20-30)")
    parser.add_argument('--list-limit', type=int, default=200, help="So muc lay tu get_siginfo de chon mau PE")
    parser.add_argument('--out-dir', default=None, help="Mac dinh: sources.malicious_dirs[0] trong configs/dataset.yaml")
    parser.add_argument('--sleep', type=float, default=1.0, help="Nghi giua 2 lan tai (giay)")
    args = parser.parse_args()

    out_dir = resolve(args.out_dir or load_config('dataset')['sources']['malicious_dirs'][0])
    os.makedirs(out_dir, exist_ok=True)
    manifest_path = os.path.join(os.path.dirname(out_dir), 'fetch_manifest.jsonl')

    session = requests.Session()
    session.headers['Auth-Key'] = load_api_key(os.path.join(REPO_ROOT, '.env'))

    entries = list_signature(session, args.signature, args.list_limit)
    pe_entries = [e for e in entries if e.get('file_type') in PE_FILE_TYPES]
    print(f"get_siginfo('{args.signature}'): {len(entries)} muc, {len(pe_entries)} la exe/dll")

    saved, skipped = [], []
    for e in pe_entries:
        if len(saved) >= args.count:
            break
        sha256 = e['sha256_hash']
        if os.path.exists(os.path.join(out_dir, sha256)):
            skipped.append((sha256, 'da co tren dia'))
            continue
        try:
            path = save_sample(download_sample(session, sha256), sha256, out_dir)
        except Exception as ex:
            skipped.append((sha256, f"{type(ex).__name__}: {ex}"))
            continue
        finally:
            time.sleep(args.sleep)
        saved.append(path)
        with open(manifest_path, 'a') as mf:
            mf.write(json.dumps({
                'sha256': sha256, 'source': 'malwarebazaar', 'signature': e.get('signature'),
                'file_type': e.get('file_type'), 'file_name': e.get('file_name'),
                'first_seen': e.get('first_seen'), 'tags': e.get('tags'),
                'fetched_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            }) + '\n')
        print(f"  [{len(saved):2d}] {sha256}  {e.get('file_type')}  first_seen={e.get('first_seen')}")

    print(f"\nDa luu {len(saved)} mau vao {out_dir}")
    if skipped:
        print(f"Bo qua {len(skipped)} mau:")
        for sha256, reason in skipped:
            print(f"  {sha256}: {reason}")
    if len(saved) < args.count:
        print(f"[CANH BAO] Chi tai duoc {len(saved)}/{args.count} mau - tang --list-limit neu can them.")


if __name__ == '__main__':
    main()
