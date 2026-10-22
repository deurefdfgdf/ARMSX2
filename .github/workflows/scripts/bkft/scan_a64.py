#!/usr/bin/env python3
"""BKFT: stdlib-only AArch64 ELF scanner for instructions the Raspberry Pi 5 (BCM2712, Cortex-A76) lacks.

Usage: python3 -I scan_a64.py <elf> [--json out.json] [--fail]

Classifies every aligned 32-bit word in executable sections by encoding mask and names the function each
hit is in (.symtab, else .dynsym). Words inside $d mapping-symbol regions (literal data in .text) are
reported separately and never fail the check.

The BCM2712 implements ARMv8.2-A with FP16, RCpc, dotprod and the ARMv8 Cryptographic Extension (AES,
PMULL 64-bit, SHA1, SHA256: "Cortex-A76 CPU, with Cryptographic Extension" in the Pi 5 product brief), so
those are reported for information only. With --fail, any other class below (SHA512/SHA3/SM3/SM4, LRCPC2+,
JSCVT, FCMA, BF16, I8MM, FHM, non-hint PAuth, FlagM, FRINTTS, SB, MTE, SVE, SME) anywhere in code is an error.
"""
import struct, sys, json, bisect, collections

# ---------------------------------------------------------------- encodings
# (class, name, mask, value, extra-predicate or None)
def size_in(*vals):
    return lambda w: ((w >> 22) & 3) in vals

ENC = [
    # ARMv8 Crypto: AES  (0100 1110 0010 1000 0 opcode 10 Rn Rd)
    ("AES", "aese",   0xFFFFFC00, 0x4E284800, None),
    ("AES", "aesd",   0xFFFFFC00, 0x4E285800, None),
    ("AES", "aesmc",  0xFFFFFC00, 0x4E286800, None),
    ("AES", "aesimc", 0xFFFFFC00, 0x4E287800, None),
    # PMULL/PMULL2 (Advanced SIMD three different, U=0, opcode 1110). size=11 -> 1Q (Crypto)
    ("PMULL64", "pmull{2} .1q,.1d/.2d", 0xBFE0FC00, 0x0EE0E000, None),
    # SHA1/SHA256 three-register (0101 1110 000 Rm 0 opc 00 Rn Rd)
    ("SHA1", "sha1c",      0xFFE0FC00, 0x5E000000, None),
    ("SHA1", "sha1p",      0xFFE0FC00, 0x5E001000, None),
    ("SHA1", "sha1m",      0xFFE0FC00, 0x5E002000, None),
    ("SHA1", "sha1su0",    0xFFE0FC00, 0x5E003000, None),
    ("SHA256", "sha256h",  0xFFE0FC00, 0x5E004000, None),
    ("SHA256", "sha256h2", 0xFFE0FC00, 0x5E005000, None),
    ("SHA256", "sha256su1",0xFFE0FC00, 0x5E006000, None),
    # SHA1/SHA256 two-register (0101 1110 0010 1000 0 opc 10 Rn Rd)
    ("SHA1", "sha1h",      0xFFFFFC00, 0x5E280800, None),
    ("SHA1", "sha1su1",    0xFFFFFC00, 0x5E281800, None),
    ("SHA256", "sha256su0",0xFFFFFC00, 0x5E282800, None),
    # 0xCE group: SHA512 / SHA3 / SM3 / SM4
    ("SHA3", "eor3",       0xFFE08000, 0xCE000000, None),
    ("SHA3", "bcax",       0xFFE08000, 0xCE200000, None),
    ("SM3",  "sm3ss1",     0xFFE08000, 0xCE400000, None),
    ("SM3",  "sm3tt*",     0xFFE0C000, 0xCE408000, None),
    ("SHA512", "sha512h",  0xFFE0FC00, 0xCE608000, None),
    ("SHA512", "sha512h2", 0xFFE0FC00, 0xCE608400, None),
    ("SHA512", "sha512su1",0xFFE0FC00, 0xCE608800, None),
    ("SHA3", "rax1",       0xFFE0FC00, 0xCE608C00, None),
    ("SM3",  "sm3partw1",  0xFFE0FC00, 0xCE60C000, None),
    ("SM3",  "sm3partw2",  0xFFE0FC00, 0xCE60C400, None),
    ("SM4",  "sm4ekey",    0xFFE0FC00, 0xCE60C800, None),
    ("SHA3", "xar",        0xFFE00000, 0xCE800000, None),
    ("SHA512", "sha512su0",0xFFFFFC00, 0xCEC08000, None),
    ("SM4",  "sm4e",       0xFFFFFC00, 0xCEC08400, None),
    # LRCPC2 (v8.4): LDAPUR*/STLUR*  (size 011001 opc 0 imm9 00 Rn Rt)
    ("LRCPC2", "ldapur*/stlur*", 0x3F200C00, 0x19000000, None),
    # Same group with bits[11:10]!=00: LRCPC3 / unallocated (v8.9)
    ("LRCPC3", "lrcpc3/unalloc 0x19 grp", 0x3F200000, 0x19000000, lambda w: (w & 0xC00) != 0),
    ("LRCPC3", "ldapur/stlur simd&fp", 0x3F200C00, 0x1D000800, None),
    # MTE (v8.5) tag load/store: 1101 1001 opc 1 ...
    ("MTE", "stg/ldg/st2g/...", 0xFF200000, 0xD9200000, None),
    # JSCVT (v8.3)
    ("FJCVTZS", "fjcvtzs", 0xFFFFFC00, 0x1E7E0000, None),
    # FCMA (v8.3) vector three-same-extra U=1 opcode 10xx / 11x0, and by-element
    ("FCMA", "fcmla (vector)", 0xBF20E400, 0x2E00C400, None),
    ("FCMA", "fcadd (vector)", 0xBF20EC00, 0x2E00E400, None),
    ("FCMA", "fcmla (element)", 0xBF009400, 0x2F001000, size_in(1, 2)),
    # BF16 / I8MM (v8.6)
    ("BF16", "bfdot (vector)",   0xBFE0FC00, 0x2E40FC00, None),
    ("BF16", "bfmmla",           0xFFE0FC00, 0x6E40EC00, None),
    ("BF16", "bfmlal[bt] (vector)", 0xBFE0FC00, 0x2EC0FC00, None),
    ("BF16", "bfdot (element)",  0xBFC0F400, 0x0F40F000, None),
    ("BF16", "bfmlal[bt] (element)", 0xBFC0F400, 0x0FC0F000, None),
    ("BF16", "bfcvtn{2}",        0xBFFFFC00, 0x0EA16800, None),
    ("BF16", "bfcvt",            0xFFFFFC00, 0x1E634000, None),
    ("I8MM", "smmla",            0xFFE0FC00, 0x4E80A400, None),
    ("I8MM", "ummla",            0xFFE0FC00, 0x6E80A400, None),
    ("I8MM", "usmmla",           0xFFE0FC00, 0x4E80AC00, None),
    ("I8MM", "usdot (vector)",   0xBFE0FC00, 0x0E809C00, None),
    ("I8MM", "sudot (element)",  0xBFC0F400, 0x0F00F000, None),
    ("I8MM", "usdot (element)",  0xBFC0F400, 0x0F80F000, None),
    # FHM (fp16fml, not on A76): FMLAL/FMLSL{2}
    ("FHM", "fmlal (vector)",    0xBFE0FC00, 0x0E20EC00, None),
    ("FHM", "fmlsl (vector)",    0xBFE0FC00, 0x0EA0EC00, None),
    ("FHM", "fmlal2 (vector)",   0xBFE0FC00, 0x2E20CC00, None),
    ("FHM", "fmlsl2 (vector)",   0xBFE0FC00, 0x2EA0CC00, None),
    ("FHM", "fmlal (element)",   0xBFC0F400, 0x0F800000, None),
    ("FHM", "fmlsl (element)",   0xBFC0F400, 0x0F804000, None),
    ("FHM", "fmlal2 (element)",  0xBFC0F400, 0x2F808000, None),
    ("FHM", "fmlsl2 (element)",  0xBFC0F400, 0x2F80C000, None),
    # PAuth (v8.3) non-hint forms
    ("PAUTH", "braa/brab/blraa/blrab/retaa/retab/eretaa/eretab(z)", 0xFE1FF800, 0xD61F0800, None),
    ("PAUTH", "ldraa/ldrab", 0xFF200400, 0xF8200400, None),
    ("PAUTH", "pac*/aut* (reg)", 0xFFFFC000, 0xDAC10000, None),
    ("PAUTH", "xpaci/xpacd",     0xFFFFFBE0, 0xDAC143E0, None),
    ("PAUTH", "pacga",           0xFFE0FC00, 0x9AC03000, None),
    # FlagM / FlagM2
    ("FLAGM", "cfinv",  0xFFFFFFFF, 0xD500401F, None),
    ("FLAGM", "xaflag", 0xFFFFFFFF, 0xD500403F, None),
    ("FLAGM", "axflag", 0xFFFFFFFF, 0xD500405F, None),
    ("FLAGM", "rmif",   0xFFE07C10, 0xBA000400, None),
    ("FLAGM", "setf8/setf16", 0xFFFFBC1F, 0x3A00080D, None),
    # FRINTTS (v8.5)
    ("FRINTTS", "frint32/64[xz] (scalar)", 0xFFBE7C00, 0x1E284000, None),
    ("FRINTTS", "frint32/64[xz] (vector)", 0x9FBFEC00, 0x0E21E800, None),
    # SB (v8.5, not hint space)
    ("SB", "sb", 0xFFFFFFFF, 0xD50330FF, None),
    # SVE / SME top-level groups
    ("SVE", "sve group (op0=0010)", 0x1E000000, 0x04000000, None),
    ("SME", "sme group (op0=1xx0000)", 0x9E000000, 0x80000000, None),
]

INFO = [
    ("PMULL8 (plain ASIMD, ok)", 0xBFE0FC00, 0x0E20E000),
    ("PAC hint-space (ok, NOP on A76)", None, None),   # handled specially
    ("BTI (hint, ok)", 0xFFFFFF3F, 0xD503241F),
    ("LDAPR (rcpc, ok)", 0x3FFFFC00, 0x38BFC000),
    ("SDOT/UDOT (dotprod, ok)", 0xBF20FC00, 0x0E009400),
    ("CRC32 (ok)", 0x7FE0E000, 0x1AC04000),
]
PAC_HINTS = {0xD503233F, 0xD50323BF, 0xD503237F, 0xD50323FF, 0xD503231F, 0xD503239F,
             0xD503235F, 0xD50323DF, 0xD50320FF, 0xD503211F, 0xD503215F, 0xD503219F, 0xD50321DF}

# index ENC by top byte for speed
BY_TOP = collections.defaultdict(list)
for e in ENC:
    cls, name, mask, val, pred = e
    if mask & 0xFF000000 == 0xFF000000:
        BY_TOP[val >> 24].append(e)
    else:
        top_mask = mask >> 24
        for b in range(256):
            if (b & top_mask) == (val >> 24):
                BY_TOP[b].append(e)

def classify(w):
    for cls, name, mask, val, pred in BY_TOP.get(w >> 24, ()):
        if (w & mask) == val and (pred is None or pred(w)):
            return cls, name
    return None

# ---------------------------------------------------------------- ELF
def read_elf(path):
    data = open(path, "rb").read()
    assert data[:4] == b"\x7fELF", "not ELF"
    assert data[4] == 2 and data[5] == 1, "need ELF64 LE"
    (e_type, e_machine, _, e_entry, e_phoff, e_shoff, _, _, _, _, e_shentsize, e_shnum, e_shstrndx) = \
        struct.unpack_from("<HHIQQQIHHHHHH", data, 16)
    assert e_machine == 183, "not AArch64 (e_machine=%d)" % e_machine
    secs = []
    for i in range(e_shnum):
        n, t, fl, addr, off, sz, link, info, align, entsz = struct.unpack_from("<IIQQQQIIQQ", data, e_shoff + i * e_shentsize)
        secs.append(dict(idx=i, name_off=n, type=t, flags=fl, addr=addr, off=off, size=sz, link=link, entsize=entsz))
    shstr = secs[e_shstrndx]
    for s in secs:
        s["name"] = cstr(data, shstr["off"] + s["name_off"])
    return data, secs

def cstr(data, off):
    end = data.index(b"\0", off)
    return data[off:end].decode("utf-8", "replace")

def read_syms(data, secs, which):
    sec = next((s for s in secs if s["type"] == which), None)
    if not sec:
        return None
    strsec = secs[sec["link"]]
    out = []
    for i in range(sec["size"] // 24):
        name, info, other, shndx, value, size = struct.unpack_from("<IBBHQQ", data, sec["off"] + i * 24)
        out.append((cstr(data, strsec["off"] + name), info & 0xF, info >> 4, shndx, value, size))
    return out

# ---------------------------------------------------------------- tiny Itanium demangler (names only)
def demangle(s):
    if not s.startswith("_Z"):
        return s
    try:
        i = 2
        parts = []
        if s[i] == "L":
            i += 1
        if s[i] == "N":
            i += 1
            while i < len(s) and s[i] in "rVKO R":
                i += 1
            while i < len(s) and s[i] != "E":
                c = s[i]
                if c.isdigit():
                    j = i
                    while s[j].isdigit():
                        j += 1
                    n = int(s[i:j]); parts.append(s[j:j + n]); i = j + n
                elif c == "S":
                    j = s.index("_", i); parts.append("S" + s[i + 1:j]); i = j + 1
                elif c == "I":   # template args: skip balanced
                    depth = 0
                    while True:
                        if s[i] == "I": depth += 1
                        elif s[i] == "E":
                            depth -= 1
                            if depth == 0:
                                i += 1; break
                        i += 1
                    parts[-1] += "<..>"
                elif c in "CD":
                    parts.append(("~" if c == "D" else "") + (parts[-1].split("<")[0] if parts else "?")); i += 2
                elif c == "L":
                    i += 1
                else:
                    break
            return "::".join(parts) + "(..)" + (s[s.index(".", 2):] if "." in s else "")
        if s[i].isdigit():
            j = i
            while s[j].isdigit():
                j += 1
            n = int(s[i:j])
            return s[j:j + n] + "(..)" + (s[s.index(".", 2):] if "." in s else "")
    except Exception:
        pass
    return s

# ---------------------------------------------------------------- main
def main():
    args = sys.argv[1:]
    path = args[0]
    jout = args[args.index("--json") + 1] if "--json" in args else None
    data, secs = read_elf(path)
    exe = [s for s in secs if s["flags"] & 0x4 and s["type"] == 1 and s["size"]]
    symtab = read_syms(data, secs, 2)
    dynsym = read_syms(data, secs, 11)
    src = "symtab" if symtab else ("dynsym" if dynsym else "none")
    syms = symtab or dynsym or []
    print("ELF:", path)
    print("exec sections:", ", ".join("%s[0x%x+0x%x]" % (s["name"], s["addr"], s["size"]) for s in exe))
    print("symbol source:", src, "| symtab entries:", len(symtab or []), "| dynsym entries:", len(dynsym or []))

    funcs = sorted({(v, sz, n) for (n, t, b, sh, v, sz) in syms if t == 2 and v})
    fstarts = [f[0] for f in funcs]
    # mapping symbols ($x / $d) for data-in-code detection
    maps = sorted((v, n[1]) for (n, t, b, sh, v, sz) in syms if n[:2] in ("$x", "$d") and (len(n) == 2 or n[2] == "."))
    mstarts = [m[0] for m in maps]
    print("FUNC symbols:", len(funcs), "| mapping symbols:", len(maps), "($d: %d)" % sum(1 for m in maps if m[1] == "d"))

    def func_of(a):
        k = bisect.bisect_right(fstarts, a) - 1
        # walk back over aliases at same start; pick one whose size covers a
        best = None
        j = k
        while j >= 0 and j >= k - 8:
            v, sz, n = funcs[j]
            if v <= a < v + max(sz, 4):
                best = funcs[j]
                break
            j -= 1
        if best:
            return best
        if k >= 0:
            v, sz, n = funcs[k]
            return (v, sz, n + " [+0x%x, outside size 0x%x]" % (a - v, sz))
        return (0, 0, "<no symbol>")

    def is_data(a):
        k = bisect.bisect_right(mstarts, a) - 1
        return k >= 0 and maps[k][1] == "d"

    counts = collections.Counter()
    counts_data = collections.Counter()
    names = collections.Counter()
    info = collections.Counter()
    hits = []
    total = 0
    for s in exe:
        base, off, n = s["addr"], s["off"], s["size"] // 4
        words = struct.unpack_from("<%dI" % n, data, off)
        total += n
        for i, w in enumerate(words):
            r = classify(w)
            a = base + 4 * i
            if r is None:
                if (w & 0xBFE0FC00) == 0x0E20E000:
                    info["PMULL8 (plain ASIMD, ok)"] += 1
                elif w in PAC_HINTS:
                    info["PAC hint-space (ok, NOP on A76)"] += 1
                continue
            cls, nm = r
            if is_data(a):
                counts_data[cls] += 1
                hits.append((a, w, cls, nm, s["name"], True))
            else:
                counts[cls] += 1
                names[(cls, nm)] += 1
                hits.append((a, w, cls, nm, s["name"], False))
    print("words scanned:", total)
    print("\n== forbidden-class hits in code ($x / unmapped) ==")
    for c, k in sorted(counts.items(), key=lambda x: -x[1]):
        print("  %-10s %d" % (c, k))
    print("  by mnemonic:", ", ".join("%s=%d" % (nm, k) for (c, nm), k in sorted(names.items())))
    print("== hits inside $d (data-in-code, never executed as code) ==")
    for c, k in sorted(counts_data.items(), key=lambda x: -x[1]):
        print("  %-10s %d" % (c, k))
    print("== informational ==")
    for k, v in info.items():
        print("  %-34s %d" % (k, v))

    per_func = collections.OrderedDict()
    for a, w, cls, nm, sec, isd in hits:
        f = func_of(a)
        key = (f[0], f[2], isd)
        d = per_func.setdefault(key, dict(addr=f[0], size=f[1], name=f[2], data=isd, sec=sec, classes=collections.Counter(), first=a, words=[]))
        d["classes"][nm] += 1
        if len(d["words"]) < 6:
            d["words"].append("0x%x:%08x" % (a, w))
    print("\n== functions with hits (%d) ==" % len(per_func))
    for k, d in sorted(per_func.items(), key=lambda x: (x[1]["data"], x[1]["addr"])):
        tot = sum(d["classes"].values())
        print("%s0x%08x size=0x%-6x %-5d %s\n      demangled: %s\n      %s\n      e.g. %s" % (
            "[DATA] " if d["data"] else "", d["addr"], d["size"], tot, d["name"], demangle(d["name"].split(" [")[0]),
            ", ".join("%s=%d" % kv for kv in sorted(d["classes"].items())), " ".join(d["words"])))
    if jout:
        json.dump(dict(counts=counts, counts_data=counts_data, info=info,
                       funcs=[dict(addr=hex(d["addr"]), name=d["name"], data=d["data"], classes=d["classes"]) for d in per_func.values()],
                       hits=[dict(addr=hex(a), word="%08x" % w, cls=c, name=nm, data=isd) for a, w, c, nm, sec, isd in hits]),
                  open(jout, "w"), indent=1)

    # ---- policy: --fail. The Cryptographic Extension is on the BCM2712; every other class fails anywhere in code.
    if "--fail" in args:
        on_bcm2712 = {"AES", "PMULL64", "SHA1", "SHA256"}
        viol = []
        for d in per_func.values():
            if d["data"]:
                continue
            base = d["name"].split(" [")[0]
            for nm, k in d["classes"].items():
                cls = next(c for c, n2, *_ in ENC if n2 == nm)
                if cls in on_bcm2712:
                    continue
                viol.append("%s: %s x%d" % (base, nm, k))
        print("\nPOLICY:", "FAIL" if viol else "PASS", "(allowed on BCM2712: AES, PMULL64, SHA1, SHA256)")
        for v in viol:
            print("  VIOLATION", v)
        sys.exit(1 if viol else 0)

if __name__ == "__main__":
    main()
