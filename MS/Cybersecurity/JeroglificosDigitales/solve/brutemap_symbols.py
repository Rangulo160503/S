# python brutemap_symbols.py
import re, base64
from collections import Counter
from pathlib import Path

ROOT = Path("out_jero")
FLAG = re.compile(r'(?:flag|bandera|ctf|hackrocks)\{[^}]+\}', re.I)  # ampliado
B64  = re.compile(r'[A-Za-z0-9+/=]{24,}')

def try_b64(s):
    t = re.sub(r'\s+','',s)
    if len(t)%4: t += '='*((4-(len(t)%4))%4)
    try: return base64.b64decode(t, validate=False).decode('utf-8','ignore')
    except Exception: return ""

def rot13(s):
    out=[]
    for ch in s:
        o=ord(ch)
        if 65<=o<=90: out.append(chr((o-65+13)%26+65))
        elif 97<=o<=122: out.append(chr((o-97+13)%26+97))
        else: out.append(ch)
    return ''.join(out)

def reverse_bits_in_byte(b):
    # 0babcdefgh -> 0bhgfedcba
    v=0
    for i in range(8):
        v = (v<<1) | ((b>>i)&1)
    return v

def bits_to_text(bitstr, chunk, off=0, reverse_per_byte=False):
    if off: bitstr = bitstr[off:]
    n = (len(bitstr)//chunk)*chunk
    if n==0: return ""
    out=[]
    if chunk==8 and reverse_per_byte:
        for i in range(0,n,8):
            b = int(bitstr[i:i+8],2)
            out.append(chr(reverse_bits_in_byte(b)))
    else:
        for i in range(0,n,chunk):
            out.append(chr(int(bitstr[i:i+chunk],2)))
    return ''.join(out)

def hunt(label, txt):
    # buscar flags directas / rot13 / base64
    found=False
    for src,tag in [(txt,"txt"), (rot13(txt),"rot13(txt)"),
                    (try_b64(txt),"b64(txt)"), (rot13(try_b64(txt)),"rot13(b64(txt))")]:
        if not src: continue
        m = FLAG.findall(src)
        if m:
            found=True
            print(f"\n[HIT] {label} :: {tag} :: {'; '.join(sorted(set(m)))}")
            # contexto
            low=src.lower()
            for f in sorted(set(m)):
                i=low.find(f.lower()); s=max(0,i-60); e=min(len(src), i+len(f)+60)
                print(src[s:e])
            break
        # también busca bloques base64 dentro de src y decodifica
        for c in set(B64.findall(src)):
            dec = try_b64(c)
            if dec:
                mm = FLAG.findall(dec)
                if mm:
                    found=True
                    print(f"\n[HIT] {label} :: embedded b64 -> {'; '.join(sorted(set(mm)))}")
                    print(dec[:300])
                    break
        if found: break
    return found

def main():
    files = sorted(ROOT.glob("readable_*.txt"))
    if not files:
        print("No hay readable_*.txt. Ejecuta primero solve.py"); return

    for p in files:
        txt = p.read_text('utf-8','ignore')
        # toma SOLO caracteres imprimibles
        chars = [ch for ch in txt if 32 <= ord(ch) <= 126]
        if not chars: 
            continue
        freq = Counter(chars)
        top = [c for c,_ in freq.most_common(10)]
        # probamos TODAS las parejas entre los 10 más frecuentes
        for i in range(len(top)):
            for j in range(i+1, len(top)):
                a, b = top[i], top[j]
                for zero,one in [(a,b),(b,a)]:
                    bitstr = ''.join('0' if ch==zero else ('1' if ch==one else '') for ch in chars)
                    if len(bitstr) < 200: 
                        continue
                    base = f"{p.name} [{repr(zero)}→0, {repr(one)}→1]"
                    # 8 bits: normal y bits invertidos por byte
                    for rev in (False, True):
                        for off in range(8):
                            t8 = bits_to_text(bitstr, 8, off, reverse_per_byte=rev)
                            if not t8: continue
                            if hunt(f"{base} :: 8b off={off} rev={rev}", t8):
                                return
                    # 7 bits
                    for off in range(7):
                        t7 = bits_to_text(bitstr, 7, off, reverse_per_byte=False)
                        if not t7: continue
                        if hunt(f"{base} :: 7b off={off}", t7):
                            return
    print("[!] No hubo match todavía con pares top y bits invertidos. Si me dices un archivo concreto, lo fijo a mano.")

if __name__ == "__main__":
    main()
