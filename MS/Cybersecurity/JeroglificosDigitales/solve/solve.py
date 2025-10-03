#!/usr/bin/env python3
import argparse, base64, binascii, os, re, sys
from pathlib import Path

FLAG_RE = re.compile(r'(flag\{[^}]+\}|bandera\{[^}]+\})', re.IGNORECASE)
B64_RE  = re.compile(r'[A-Za-z0-9+/=]{24,}')

def only_bits(s:str)->str:
    return re.sub(r'[^01]','', s)

def bits_to_text(bits:str, chunk:int, offset:int=0)->str:
    if offset>0: bits = bits[offset:]
    n = (len(bits)//chunk)*chunk
    if n<=0: return ""
    out = []
    for i in range(0, n, chunk):
        try:
            out.append(chr(int(bits[i:i+chunk], 2)))
        except ValueError:
            out.append('?')
    return ''.join(out)

def bits_to_bytes(bits:str, offset:int=0)->bytes:
    if offset>0: bits = bits[offset:]
    n = (len(bits)//8)*8
    if n<=0: return b""
    b = bytearray(n//8)
    j = 0
    for i in range(0, n, 8):
        b[j] = int(bits[i:i+8], 2); j+=1
    return bytes(b)

def is_printable_ratio(s:str)->float:
    if not s: return 0.0
    ok = sum(1 for ch in s if 9 <= ord(ch) <= 126 or ch in '\r\n\t')
    return ok / max(1, len(s))

def rot13(s:str)->str:
    out=[]
    for ch in s:
        c=ord(ch)
        if 65<=c<=90: out.append(chr((c-65+13)%26+65))
        elif 97<=c<=122: out.append(chr((c-97+13)%26+97))
        else: out.append(ch)
    return ''.join(out)

def try_b64(s:str)->str:
    t = re.sub(r'\s+', '', s)
    if len(t)%4: t += '='*((4-(len(t)%4))%4)
    try:
        return base64.b64decode(t, validate=False).decode('utf-8', 'ignore')
    except Exception:
        try:
            return base64.b64decode(t).decode('utf-8', 'ignore')
        except Exception:
            return ""

def magic_header(b:bytes)->str:
    if len(b)<4: return "short"
    h4 = b[:4]
    if h4.startswith(b'PK\x03\x04'): return "ZIP"
    if h4.startswith(b'%PDF'):       return "PDF"
    if b[:8].startswith(b'\x89PNG\r\n\x1a\n'): return "PNG"
    if b[:3]==b'\xff\xd8\xff':       return "JPG"
    return "unknown"

def write_text(p:Path, name:str, content:str):
    (p/name).write_text(content, encoding='utf-8', errors='ignore')

def main():
    ap = argparse.ArgumentParser(description="Jeroglíficos Digitales — decoder")
    ap.add_argument("path", help="Ruta del archivo binario (0/1)")
    ap.add_argument("-o","--out", help="Carpeta de salida", default="out_jero")
    args = ap.parse_args()

    src = Path(args.path).expanduser()
    if not src.exists():
        print(f"[!] No existe: {src}", file=sys.stderr); sys.exit(1)

    outdir = Path(args.out); outdir.mkdir(parents=True, exist_ok=True)

    bits = only_bits(src.read_text(encoding='utf-8', errors='ignore'))
    if not bits:
        print("[!] El archivo no contiene bits 0/1 reconocibles."); sys.exit(1)

    report = []
    report.append(f"[+] Bits totales: {len(bits)}")

    # --- Fase 1: 8/7 bits sin/x con offset, buscar flags y base64 ---
    found_flags = set()
    interesting_b64 = []

    for scheme, chunk, max_off in (("8bits",8,8), ("7bits",7,7)):
        for off in range(max_off):
            txt = bits_to_text(bits, chunk, off)
            write_text(outdir, f"decode_offset{off}_{scheme}.txt", txt)
            m = FLAG_RE.findall(txt)
            if m:
                for f in m: found_flags.add(f)
                report.append(f"[★] FLAG en {scheme} offset={off}: {', '.join(sorted(set(m)))}")
            # base64 candidatos
            cands = list(dict.fromkeys(B64_RE.findall(txt)))
            for c in cands:
                dec = try_b64(c)
                if dec:
                    interesting_b64.append((scheme, off, c[:60]+"...", dec[:120]))
                    m2 = FLAG_RE.findall(dec)
                    if m2:
                        for f in m2: found_flags.add(f)
                        report.append(f"[★] FLAG en Base64 ({scheme} off={off}) -> {', '.join(sorted(set(m2)))}")

    # --- Fase 2: ROT13 del texto visible de 8 bits offset 0 (señuelo) ---
    t0 = bits_to_text(bits, 8, 0)
    write_text(outdir, "rot13_offset0_8bits.txt", rot13(t0))

    # --- Fase 3: XOR brute (0..255) por offset (8 bits) ---
    for off in range(8):
        b = bits_to_bytes(bits, off)
        if not b: continue
        best_reads = 0
        for k in range(256):
            x = bytes([bb ^ k for bb in b])
            try:
                txt = x.decode('utf-8', 'ignore')
            except Exception:
                continue

            # a) flag directa
            m = FLAG_RE.findall(txt)
            if m:
                for f in m: found_flags.add(f)
                write_text(outdir, f"flag_offset{off}_xor{k}.txt", txt)
                report.append(f"[★] FLAG directa XOR (off={off}, key={k}) -> {', '.join(sorted(set(m)))}")
                break

            # b) base64 plausible (todo el bloque o fragmentos largos)
            compact = re.sub(r'\s+', '', txt)
            if len(compact)>=24 and re.fullmatch(r'[A-Za-z0-9+/=]+', compact or ''):
                dec = try_b64(compact)
                if dec:
                    m2 = FLAG_RE.findall(dec)
                    if m2:
                        for f in m2: found_flags.add(f)
                        write_text(outdir, f"flag_b64_offset{off}_xor{k}.txt", dec)
                        report.append(f"[★] FLAG en Base64 -> XOR (off={off}, key={k}) -> {', '.join(sorted(set(m2)))}")
                        break

            # c) texto imprimible: guardar hasta 3 muestras por offset
            if best_reads < 3 and is_printable_ratio(txt) >= 0.95 and len(txt)>=60:
                write_text(outdir, f"readable_offset{off}_xor{k}.txt", txt)
                best_reads += 1

    # --- Fase 4: dump .bin por offset + detectar magics ---
    for off in range(8):
        b = bits_to_bytes(bits, off)
        if not b: continue
        p = outdir / f"offset_{off}.bin"
        p.write_bytes(b)
        report.append(f"[+] offset_{off}.bin -> {magic_header(b)} ({min(len(b),16)}B head: {b[:16].hex(' ').upper()})")

    # --- Resumen ---
    if found_flags:
        report.append("\n[✓] FLAGS ENCONTRADAS:")
        for f in sorted(found_flags):
            report.append(f"    {f}")
    else:
        report.append("\n[!] No se detectaron flags directas aún. Revisa:")
        report.append("    - readable_offset*_xor*.txt")
        report.append("    - flag_b64_offset*_xor*.txt (si existen)")
        report.append("    - offset_*.bin (mágicos: ZIP/PDF/PNG/JPG)")

    if interesting_b64:
        report.append("\n[ℹ] Posibles bloques Base64 (preview):")
        for sch,off,c,dec in interesting_b64[:10]:
            report.append(f"    [{sch} off={off}] {c} -> {dec!r}")

    (outdir/"report.txt").write_text("\n".join(report), encoding='utf-8')
    print(f"[OK] Hecho. Carpeta de salida: {outdir}")
    print("     Lee out_jero/report.txt y busca archivos con 'flag' o 'readable' o 'offset_*.bin'.")

if __name__ == "__main__":
    main()
