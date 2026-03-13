from __future__ import annotations

import os
import re
import subprocess
from typing import Any, Dict, Iterable, List, Tuple


def elf_bits(path: str) -> int:
    try:
        with open(path, "rb") as f:
            hdr = f.read(5)
        if len(hdr) < 5 or hdr[:4] != b"\x7fELF":
            return 0
        klass = int(hdr[4])
        if klass == 1:
            return 32
        if klass == 2:
            return 64
    except Exception:
        return 0
    return 0


def elf_arch(path: str) -> str:
    try:
        with open(path, "rb") as f:
            hdr = f.read(0x20)
        if len(hdr) < 0x14 or hdr[:4] != b"\x7fELF":
            return ""
        endian = hdr[5] if len(hdr) > 5 else 1
        if endian == 2:
            em = int.from_bytes(hdr[18:20], "big", signed=False)
        else:
            em = int.from_bytes(hdr[18:20], "little", signed=False)
        if em == 3:
            return "i386"
        if em == 62:
            return "amd64"
        if em == 40:
            return "arm"
        if em == 183:
            return "aarch64"
    except Exception:
        return ""
    return ""


def abi_info(path: str) -> Dict[str, Any]:
    raw = str(path or "").strip()
    ap = os.path.abspath(raw) if raw else ""
    exists = bool(ap and os.path.isfile(ap))
    bits = elf_bits(ap) if exists else 0
    arch = elf_arch(ap) if exists else ""
    if (not arch) and bits == 64:
        arch = "amd64"
    elif (not arch) and bits == 32:
        arch = "i386"
    return {
        "path": ap,
        "exists": exists,
        "bits": int(bits or 0),
        "arch": str(arch or "").strip(),
        "name": os.path.basename(ap) if ap else "",
    }


def stack_probe_command(abi: Dict[str, Any]) -> Tuple[str, int]:
    arch = str((abi or {}).get("arch", "")).strip().lower()
    bits = int((abi or {}).get("bits", 0) or 0)
    if arch == "i386" or bits == 32:
        return "x/16wx $esp", 4
    return "x/24gx $rsp", 8


def parse_signal(text: str) -> str:
    raw = str(text or "")
    m = re.search(r"Program received signal\s+([A-Z0-9_]+)", raw)
    if m:
        return str(m.group(1)).strip()
    m = re.search(
        r"\b(SIGHUP|SIGINT|SIGQUIT|SIGILL|SIGTRAP|SIGABRT|SIGBUS|SIGFPE|SIGKILL|SIGSEGV|SIGPIPE|SIGALRM|SIGTERM)\b",
        raw,
    )
    if m:
        return str(m.group(1)).strip()
    m = re.search(r"signal\s+([A-Z0-9_]+)", raw, re.IGNORECASE)
    if m:
        return str(m.group(1)).strip().upper()
    return ""


def parse_register_hex(text: str, *names: str) -> str:
    raw = str(text or "")
    for name in names:
        if not str(name or "").strip():
            continue
        m = re.search(rf"\b{re.escape(str(name))}\s+(0x[0-9a-fA-F]+)", raw)
        if m:
            return str(m.group(1)).strip()
    return ""


def parse_rip(reg_text: str) -> str:
    return parse_register_hex(reg_text, "rip", "eip", "pc")


def parse_fault_address(text: str) -> str:
    raw = str(text or "")
    patterns = [
        r"Cannot access memory at address\s+(0x[0-9a-fA-F]+)",
        r"fault addr(?:ess)?[:=\s]+(0x[0-9a-fA-F]+)",
        r"si_addr[:=\s]+(0x[0-9a-fA-F]+)",
    ]
    for pat in patterns:
        m = re.search(pat, raw, re.IGNORECASE)
        if m:
            return str(m.group(1)).strip().lower()
    return ""


def extract_stack_lines(text: str, max_lines: int = 8) -> List[str]:
    raw = str(text or "")
    out: List[str] = []
    for line in raw.splitlines():
        s = str(line or "").rstrip()
        if not re.match(r"^\s*0x[0-9a-fA-F]+:\s+0x[0-9a-fA-F]+", s):
            continue
        out.append(s)
        if len(out) >= max(1, int(max_lines or 8)):
            break
    return out


def parse_stack_words(text: str, max_lines: int = 8) -> List[str]:
    out: List[str] = []
    for line in extract_stack_lines(text, max_lines=max_lines):
        try:
            _addr, payload = line.split(":", 1)
        except ValueError:
            continue
        for token in payload.split():
            s = str(token or "").strip().lower()
            if re.fullmatch(r"0x[0-9a-f]+", s):
                out.append(s)
    return out


def parse_stack_top_word(text: str) -> str:
    words = parse_stack_words(text, max_lines=1)
    return words[0] if words else ""


def parse_stack_top_qword(text: str) -> str:
    return parse_stack_top_word(text)


def parse_pie_base(text: str, binary_path: str) -> str:
    raw = str(text or "")
    bin_path = os.path.abspath(str(binary_path or "").strip())
    if not raw or not bin_path:
        return ""
    bin_name = os.path.basename(bin_path)
    for line in raw.splitlines():
        if (bin_path not in line) and (bin_name not in line):
            continue
        s = str(line or "").strip()
        if not s:
            continue
        toks = s.split()
        if len(toks) < 2:
            continue
        tok0 = toks[0].strip()
        objfile = toks[-1].strip()
        if objfile not in {bin_path, bin_name} and (not objfile.endswith('/' + bin_name)):
            continue
        if re.fullmatch(r"0x[0-9a-fA-F]+", tok0):
            return tok0.lower()
        if re.fullmatch(r"[0-9a-fA-F]+", tok0):
            return "0x" + tok0.lower()
    return ""


def infer_static_stack_smash_offset(binary_path: str) -> int:
    bin_abs = os.path.abspath(str(binary_path or "").strip())
    if not bin_abs or (not os.path.isfile(bin_abs)):
        return 0
    bits = int(elf_bits(bin_abs) or 0)
    frame_ptr_size = 4 if bits == 32 else 8
    try:
        proc = subprocess.run(
            ["objdump", "-d", bin_abs],
            text=True,
            capture_output=True,
            check=False,
            timeout=2.5,
        )
    except Exception:
        return 0
    if int(0 if proc.returncode is None else proc.returncode) != 0:
        return 0
    lines = str(proc.stdout or "").splitlines()
    current_sub = 0
    last_buf_off = 0
    vulnerable_seen = False
    best = 0
    for raw_line in lines:
        line = str(raw_line or "")
        if re.match(r"^[0-9a-fA-F]+\s+<.+>:$", line.strip()):
            current_sub = 0
            last_buf_off = 0
            vulnerable_seen = False
            continue
        m_sub = re.search(r"\bsub\s+\$0x([0-9a-fA-F]+),%[er]?sp\b", line)
        if m_sub:
            try:
                current_sub = int(m_sub.group(1), 16)
            except Exception:
                current_sub = 0
        m_lea = re.search(r"\blea\s+-0x([0-9a-fA-F]+)\(%[er]?bp\),%[a-z0-9]+\b", line)
        if m_lea:
            try:
                last_buf_off = int(m_lea.group(1), 16)
            except Exception:
                last_buf_off = 0
        if re.search(r"\bcall\b.*<(gets|fgets|read|recv|__isoc99_scanf|scanf)@", line):
            vulnerable_seen = True
        if vulnerable_seen and last_buf_off > 0:
            candidate = int(last_buf_off + frame_ptr_size)
            if current_sub > 0 and last_buf_off > current_sub:
                continue
            if 0 < candidate <= 4096:
                best = max(best, candidate)
                vulnerable_seen = False
    return int(best or 0)


def cyclic_bytes(length: int) -> bytes:
    n = max(1, int(length))
    set1 = b"abcdefghijklmnopqrstuvwxyz"
    set2 = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    set3 = b"0123456789"
    out = bytearray()
    for a in set1:
        for b in set2:
            for c in set3:
                out.extend((a, b, c))
                if len(out) >= n:
                    return bytes(out[:n])
    while len(out) < n:
        out.extend(b"Aa0")
    return bytes(out[:n])


def _de_bruijn_bytes(alphabet: bytes, subseq_len: int, length: int) -> bytes:
    alpha = bytes(alphabet or b"")
    k = len(alpha)
    n = max(1, int(subseq_len or 1))
    want = max(1, int(length or 1))
    if k <= 0:
        return b"A" * want
    a = [0] * (k * n)
    seq = bytearray()

    def db(t: int, p: int) -> None:
        if len(seq) >= want + n:
            return
        if t > n:
            if n % p == 0:
                for j in range(1, p + 1):
                    seq.append(alpha[a[j]])
        else:
            a[t] = a[t - p]
            db(t + 1, p)
            for j in range(a[t - p] + 1, k):
                a[t] = j
                db(t + 1, t)

    db(1, 1)
    if seq:
        seq.extend(seq[: n - 1])
    while len(seq) < want:
        seq.extend(alpha[:1] or b"A")
    return bytes(seq[:want])


def cyclic_bytes_pwntools_lower(length: int, subseq_len: int = 4) -> bytes:
    return _de_bruijn_bytes(b"abcdefghijklmnopqrstuvwxyz", subseq_len, length)


def cyclic_bytes_lower_triplet(length: int) -> bytes:
    n = max(1, int(length))
    out = bytearray()
    alpha = b"abcdefghijklmnopqrstuvwxyz"
    for a in alpha:
        for b in alpha:
            for c in alpha:
                out.extend((a, b, c))
                if len(out) >= n:
                    return bytes(out[:n])
    while len(out) < n:
        out.extend(b"aaa")
    return bytes(out[:n])


def cyclic_find_offset(value_hex: str, max_len: int) -> int:
    s = str(value_hex or "").strip().lower()
    if not s:
        return -1
    if s.startswith("0x"):
        s = s[2:]
    if not re.fullmatch(r"[0-9a-f]+", s):
        return -1
    try:
        v = int(s, 16)
    except Exception:
        return -1
    if v <= 0:
        return -1
    patterns = [
        cyclic_bytes(max(64, int(max_len) + 16)),
        cyclic_bytes_pwntools_lower(max(64, int(max_len) + 16), subseq_len=4),
        cyclic_bytes_lower_triplet(max(64, int(max_len) + 16)),
    ]
    b8 = int(v).to_bytes(8, byteorder="little", signed=False)
    best_idx = -1
    best_len = 0
    for pat in patterns:
        idx = pat.find(b8)
        if idx >= 0:
            return int(idx)
        idx = pat.find(b8[:4])
        if idx >= 0:
            return int(idx)
        for start in range(len(b8)):
            max_sub_len = len(b8) - start
            for sub_len in range(max_sub_len, 3, -1):
                idx = pat.find(b8[start : start + sub_len])
                if idx >= 0 and (sub_len > best_len or (sub_len == best_len and (best_idx < 0 or idx > best_idx))):
                    best_idx = idx
                    best_len = sub_len
                    break
    if best_idx >= 0:
        return int(best_idx)
    return -1


def recover_cyclic_offset(
    value_hex: str,
    stack_words: Iterable[str],
    cyclic_len: int,
    stack_word_size: int = 8,
    extra_values: Iterable[Tuple[str, str]] | None = None,
) -> Tuple[int, str]:
    off = cyclic_find_offset(value_hex, cyclic_len)
    if off >= 0:
        return int(off), "rip"
    for source_name, extra_value in list(extra_values or []):
        off = cyclic_find_offset(extra_value, cyclic_len)
        if off >= 0:
            return int(off), str(source_name or "aux")
    source = "esp" if int(stack_word_size or 0) == 4 else "rsp"
    for word in stack_words:
        off = cyclic_find_offset(word, cyclic_len)
        if off >= 0:
            return int(off), source
    return -1, ""


def recover_offset_hints(
    *,
    value_hex: str,
    stack_words: Iterable[str],
    cyclic_len: int,
    stack_word_size: int = 8,
    fault_addr: str = "",
    static_guess: int = 0,
) -> Dict[str, Any]:
    extra_offset_values = []
    if str(fault_addr or "").strip():
        extra_offset_values.append(("fault", str(fault_addr).strip()))
    offset_to_rip, offset_source = recover_cyclic_offset(
        value_hex,
        stack_words,
        cyclic_len,
        stack_word_size=int(stack_word_size or 0),
        extra_values=extra_offset_values,
    )
    fault_offset_candidate = 0
    static_offset_candidate = 0
    if str(offset_source or "") == "fault" and offset_to_rip >= 0:
        fault_offset_candidate = int(offset_to_rip)
        offset_to_rip = -1
        offset_source = ""
    guessed = int(static_guess or 0)
    word_size = int(stack_word_size or 8)
    if offset_to_rip < 0 and fault_offset_candidate > 0 and guessed > 0:
        if guessed <= (int(cyclic_len or 0) + word_size):
            if abs(int(guessed) - int(fault_offset_candidate)) <= word_size:
                static_offset_candidate = int(guessed)
    control_rip = bool(offset_to_rip >= 0)
    if not control_rip:
        offset_to_rip = 0
        offset_source = ""
    return {
        "offset_to_rip": int(offset_to_rip),
        "offset_source": str(offset_source or ""),
        "fault_offset_candidate": int(fault_offset_candidate),
        "static_offset_candidate": int(static_offset_candidate),
        "control_rip": bool(control_rip),
    }


def hex_to_int(x: str) -> int:
    try:
        return int(str(x).strip(), 16)
    except Exception:
        return 0


def compute_pc_offset(rip: str, pie_base: str) -> str:
    rv = hex_to_int(rip)
    pv = hex_to_int(pie_base)
    if rv <= 0:
        return ""
    if pv < 0:
        return ""
    if rv < pv:
        return ""
    off = rv - pv
    if off < 0 or off > 0x2000000:
        return ""
    return hex(off)
