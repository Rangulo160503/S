# python digits_ascii_decode.py
import re
from pathlib import Path

ROOT = Path("out_jero")
FILES = sorted(list(ROOT.glob("decode_offset*_8bits.txt"))) + sorted(list(ROOT.glob("readable_*.txt")))

# Mapeo de superíndices y símbolos a dígitos
SUP = {
    '¹':'1','²':'2','³':'3','⁴':'4','⁵':'5','⁶':'6','⁷':'7','⁸':'8','⁹':'9','⁰':'0',
    'º':'0','°':'0'  # ordinal/degree como 0
}

FLAG_RE = re.compile(r'(flag\{[^}]+\}|bandera\{[^}]+\})', re.I)

def normalize_digits(s: str) -> str:
    return ''.join(SUP.get(ch, ch) for ch in s)

def chunk_token_to_ascii(token: str) -> str:
    """
    Parte una tira de dígitos en códigos ASCII decimales (2–3 dígitos) usando
    heurística: preferir 3 dígitos si 100–126, si no, 2 dígitos si 32–99.
    """
    out = []
    i = 0
    n = len(token)
    while i < n:
        # intenta 3 dígitos si alcanza
        if i+3 <= n:
            v3 = int(token[i:i+3])
            if 100 <= v3 <= 126:
                out.append(chr(v3)); i += 3; continue
        # intenta 2 dígitos
        if i+2 <= n:
            v2 = int(token[i:i+2])
            if 32 <= v2 <= 99:
                out.append(chr(v2)); i += 2; continue
        # si no cuadra, avanza 1 dígito (ruido)
        i += 1
    return ''.join(out)

def decode_file(p: Path):
    txt = p.read_text(encoding='utf-8', errors='ignore')
    norm = normalize_digits(txt)
    # extrae “tokens” numéricos (cortes en cualquier no-dígito)
    tokens = re.findall(r'\d+', norm)
    pieces = []
    for t in tokens:
        if 1 <= len(t) <= 3:
            v = int(t)
            if 32 <= v <= 126:
                pieces.append(chr(v))
            elif 0 <= v <= 255:
                # puede ser byte fuera de printable; lo ignoramos
                pass
        elif len(t) > 3:
            pieces.append(chunk_token_to_ascii(t))
    out = ''.join(pieces)
    return out

def main():
    any_flag = False
    if not FILES:
        print("No hay decode_offset*_8bits.txt ni readable_*.txt. Corre primero solve.py")
        return
    for f in FILES:
        out = decode_file(f)
        if not out:
            continue
        m = FLAG_RE.findall(out)
        if m:
            any_flag = True
            print(f"\n[HIT] {f.name} -> {', '.join(sorted(set(m)))}")
            # muestra contexto
            for flag in sorted(set(m)):
                idx = out.lower().find(flag.lower())
                s = max(0, idx-60); e = min(len(out), idx+len(flag)+60)
                print(out[s:e])
        else:
            # si no hay flag, muestra una vista corta si parece legible
            leg = sum(32<=ord(c)<=126 or c in '\n\r\t' for c in out)/max(1,len(out))
            if leg > 0.7 and len(out) > 80:
                print(f"\n[INFO] legible {f.name}:\n{out[:200]}...")
    if not any_flag:
        print("\n[!] Sin flag aún con decimales camuflados. Mira las [INFO] o dime qué archivo se ve más limpio.")

if __name__ == "__main__":
    main()
