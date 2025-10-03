# python decode_pair_quick.py
import re, base64
from pathlib import Path

ROOT = Path("out_jero")
FLAG = re.compile(r'(flag\{[^}]+\}|bandera\{[^}]+\})', re.I)

PAIR_HINTS = [
    ("xor61",  "!", "e"),
    ("xor120", "X", "8"),
    ("xor122", "Z", ":"),
]

def try_b64(s):
    t = re.sub(r'\s+', '', s)
    if len(t)%4: t += '='*((4-(len(t)%4))%4)
    try: return base64.b64decode(t).decode('utf-8','ignore')
    except: return ""

def bits_to_text(bits, chunk, off=0):
    if off: bits = bits[off:]
    n = (len(bits)//chunk)*chunk
    return ''.join(chr(int(bits[i:i+chunk],2)) for i in range(0,n,chunk))

def hunt(label, txt):
    hit = False
    m = FLAG.findall(txt)
    if m:
        hit=True
        print(f"\n[HIT] {label} :: {'; '.join(sorted(set(m)))}")
        # contexto alrededor
        low = txt.lower()
        for f in sorted(set(m)):
            i = low.find(f.lower()); s=max(0,i-60); e=min(len(txt), i+len(f)+60)
            print(txt[s:e])
    # por si todo el bloque es Base64
    for c in set(re.findall(r'[A-Za-z0-9+/=]{24,}', txt)):
        dec = try_b64(c)
        if dec:
            m2 = FLAG.findall(dec)
            if m2:
                hit=True
                print(f"\n[HIT] {label} :: Base64→texto :: {'; '.join(sorted(set(m2)))}")
                print(dec[:300])
    return hit

def main():
    files = sorted(ROOT.glob("readable_*.txt"))
    if not files:
        print("No hay readable_*.txt. Ejecuta primero solve.py")
        return

    for p in files:
        name = p.name
        txt  = p.read_text('utf-8','ignore')
        for key,a,b in PAIR_HINTS:
            if key not in name: 
                continue
            for zero,one in [(a,b),(b,a)]:
                bits = ''.join('0' if ch==zero else ('1' if ch==one else '') 
                               for ch in txt if not ch.isspace())
                if len(bits) < 64: 
                    continue
                base = f"{name} [{zero}→0, {one}→1]"
                # 8 bits
                for off in range(8):
                    t8 = bits_to_text(bits,8,off)
                    if hunt(f"{base} :: 8b off={off}", t8): 
                        return
                    dec = try_b64(t8)
                    if dec and hunt(f"{base} :: FromBase64(8b off={off})", dec): 
                        return
                # 7 bits
                for off in range(7):
                    t7 = bits_to_text(bits,7,off)
                    if hunt(f"{base} :: 7b off={off}", t7): 
                        return
                    dec = try_b64(t7)
                    if dec and hunt(f"{base} :: FromBase64(7b off={off})", dec): 
                        return

    print("[!] No hubo hit con los mapeos sugeridos. Podemos probar otro par específico si me dices el archivo más 'limpio'.")

if __name__ == "__main__":
    main()
