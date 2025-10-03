# guarda como symbol_pairs_decode.py y ejecuta: python symbol_pairs_decode.py
import re, base64
from pathlib import Path

ROOT = Path("out_jero")
FLAG = re.compile(r'(flag\{[^}]+\}|bandera\{[^}]+\})', re.I)

def try_b64(s):
    t = re.sub(r'\s+', '', s)
    if len(t)%4: t += '='*((4-(len(t)%4))%4)
    try: return base64.b64decode(t).decode('utf-8','ignore')
    except: return ""

def bits_to_text(bits, chunk, off=0):
    if off: bits = bits[off:]
    n = (len(bits)//chunk)*chunk
    return ''.join(chr(int(bits[i:i+chunk],2)) for i in range(0,n,chunk))

def hunt(txt, tag):
    hit=False
    m = FLAG.findall(txt)
    if m:
        hit=True
        print(f"\n[HIT] {tag} :: {'; '.join(sorted(set(m)))}")
        # contexto
        low=txt.lower()
        for f in sorted(set(m)):
            i=low.find(f.lower()); s=max(0,i-60); e=min(len(txt), i+len(f)+60)
            print(txt[s:e])
    # por si lo decodificado es Base64
    for c in set(re.findall(r'[A-Za-z0-9+/=]{24,}', txt)):
        dec = try_b64(c)
        if dec:
            m2 = FLAG.findall(dec)
            if m2:
                hit=True
                print(f"\n[HIT] {tag} :: Base64→texto :: {'; '.join(sorted(set(m2)))}")
                print(dec[:300])
    return hit

# pares candidatos por tipo de archivo (se prueban en ambos sentidos 0/1)
PAIR_HINTS = {
    'xor61': [('!','e')],
    'xor120':[('X','8')],
    'xor122':[('Z',':')],
    # puedes añadir más si ves otro patrón dominante:
    # 'xor60':[('|',']'), ('|','?'), (']','?')],
}

def decode_file(p: Path):
    name = p.name
    txt = p.read_text('utf-8','ignore')
    key = None
    for k in PAIR_HINTS:
        if k in name:
            key = k; break
    pairs = PAIR_HINTS.get(key, [])
    if not pairs:
        return False

    any_hit=False
    for a,b in pairs:
        for zero,one in [(a,b),(b,a)]:
            # solo conserva a/b y mapea a→0, b→1
            bits = ''.join('0' if ch==zero else ('1' if ch==one else '') for ch in txt if not ch.isspace())
            if len(bits) < 64: 
                continue

            tag = f"{name} [{zero}→0, {one}→1]"
            # 8 bits con offsets
            for off in range(8):
                t8 = bits_to_text(bits,8,off)
                if hunt(t8, f"{tag} :: 8b off={off}"):
                    return True
                dec = try_b64(t8)
                if dec and hunt(dec, f"{tag} :: FromBase64(8b off={off})"):
                    return True
            # 7 bits con offsets
            for off in range(7):
                t7 = bits_to_text(bits,7,off)
                if hunt(t7, f"{tag} :: 7b off={off}"):
                    return True
                dec = try_b64(t7)
                if dec and hunt(dec, f"{tag} :: FromBase64(7b off={off})"):
                    return True
    return any_hit

def main():
    files = sorted(ROOT.glob("readable_*.txt"))
    if not files:
        print("No hay readable_*.txt. Ejecuta primero solve.py")
        return
    hit=False
    for p in files:
        if decode_file(p):
            hit=True
            break
    if not hit:
        print("[!] Aún sin flag con mapeos sugeridos. Dime sobre qué archivo insistimos y ajusto el par.")

if __name__ == "__main__":
    main()
