# python scan_networkish.py
import re, base64
from pathlib import Path

ROOT = Path("out_jero")
FLAG = re.compile(r'(flag\{[^}]+\}|bandera\{[^}]+\})', re.I)
B64  = re.compile(r'[A-Za-z0-9+/=]{24,}')

def rot13(s):
    out=[]
    for ch in s:
        c=ord(ch)
        if 65<=c<=90: out.append(chr((c-65+13)%26+65))
        elif 97<=c<=122: out.append(chr((c-97+13)%26+97))
        else: out.append(ch)
    return ''.join(out)

def try_b64(s):
    t=re.sub(r'\s+','',s)
    if len(t)%4: t += '='*((4-(len(t)%4))%4)
    try: return base64.b64decode(t).decode('utf-8','ignore')
    except: return ""

def ints_from_text(t):  # extrae enteros decimales
    return [int(m) for m in re.findall(r'\d+', t)]

def scan_numbers(name, txt):
    nums = ints_from_text(txt)
    if not nums: return False
    hit=False

    # bytes directos (0..255)
    by = [n for n in nums if 0 <= n <= 255]
    if len(by) >= 8:
        s = ''.join(chr(b) for b in by)
        if FLAG.search(s): print(f"[HIT] bytes->ASCII :: {name}\n{s[:300]}"); hit=True
        r = rot13(s)
        if FLAG.search(r): print(f"[HIT] bytes->ROT13 :: {name}\n{r[:300]}"); hit=True

    # grupos de 4 como octetos IPv4 → ASCII
    if len(by) >= 4:
        s = ''.join(chr(b) for b in by)  # mismo stream, pero pensado como “octetos”
        if FLAG.search(s): print(f"[HIT] IPv4-octets->ASCII :: {name}\n{s[:300]}"); hit=True

    # pares 16-bit big endian
    if len(by) >= 2:
        be = []
        for i in range(0,len(by)-1,2):
            v = ((by[i]&0xFF)<<8) | (by[i+1]&0xFF)
            if 0 <= v <= 0x10FFFF: be.append(v)
        if be:
            try:
                s = ''.join(chr(v) for v in be)
                if FLAG.search(s): print(f"[HIT] 16bit-BE->text :: {name}\n{s[:300]}"); hit=True
            except: pass

    # pares 16-bit little endian
    if len(by) >= 2:
        le = []
        for i in range(0,len(by)-1,2):
            v = ((by[i+1]&0xFF)<<8) | (by[i]&0xFF)
            if 0 <= v <= 0x10FFFF: le.append(v)
        if le:
            try:
                s = ''.join(chr(v) for v in le)
                if FLAG.search(s): print(f"[HIT] 16bit-LE->text :: {name}\n{s[:300]}"); hit=True
            except: pass

    # pistas legibles
    if not hit:
        s = ''.join(chr(b) for b in by)
        ratio = sum(32<=ord(c)<=126 or c in '\n\r\t' for c in s)/max(1,len(s))
        if ratio > 0.8:
            print(f"[INFO] legible :: {name}\n{s[:200]}")
    return hit

def main():
    found=False
    for p in sorted(ROOT.glob("readable_*.txt")):
        txt = p.read_text('utf-8','ignore')
        # flag directa / rot13 / base64
        for src in (txt, rot13(txt)):
            m = FLAG.findall(src)
            if m: print(f"[HIT] direct/rot13 :: {p.name} :: {', '.join(m)}"); found=True
            for c in set(B64.findall(src)):
                dec = try_b64(c)
                if dec:
                    if FLAG.search(dec):
                        print(f"[HIT] b64->text :: {p.name}\n{dec[:300]}"); found=True
                    r = rot13(dec)
                    if FLAG.search(r):
                        print(f"[HIT] b64->rot13 :: {p.name}\n{r[:300]}"); found=True
        # redes: números
        if scan_numbers(p.name, txt): found=True
    if not found:
        print("[!] Sin flag aún. Dime cuál readable_* se ve 'menos ruido' y lo ataco directo.")

if __name__ == "__main__":
    main()