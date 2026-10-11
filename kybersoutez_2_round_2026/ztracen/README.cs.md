<div align="center">

# 🔐 ZtraceN

[🇬🇧 English](README.md) · 🇨🇿 **Čeština**

</div>

## Kybersoutěž 2. kolo 2026

> **Kybersoutěž** je česká národní soutěž v kybernetické bezpečnosti určená studentům základních, středních i vysokých škol ve věku 9–24 let. Je pořádána ve formátu CTF a jejím cílem je rozvíjet digitální dovednosti, vyhledávat talenty a zvyšovat povědomí o kybernetických hrozbách mezi mladou generací v České republice.

### Zadání

**Zadání:**

> Ale ne! Alice a Bob si hráli s RSA, ale bohužel ztratili modul a nyní nemohou dešifrovat jejich zprávu. Pomůžeš jim najít ztracený modul a dešifrovat tak zprávu?
>
> - Veřejný exponent: `65537`
> - Soukromý exponent: `13732020974556595981129643152379568337833162459237646942961543641211348147598702041965557184544837721933671794341920150450664179941113857`
> - Zašifrovaná zpráva: `0x33743816105f6f521b7e618f7bef65a35a90dcba800cdbc7419c12965abc433081646c515c0af14c55a35a5debb60a275d228397ce1179927`
>
> Vlajka je ve formátu `HCKR{...}`.

---

### Řešení

```bash
pip install pycryptodome
```

```python
from itertools import combinations_with_replacement, product

from Crypto.Util.number import isPrime


e = 65537
d = 13732020974556595981129643152379568337833162459237646942961543641211348147598702041965557184544837721933671794341920150450664179941113857
c = 0x33743816105f6f521b7e618f7bef65a35a90dcba800cdbc7419c12965abc433081646c515c0af14c55a35a5debb60a275d228397ce1179927

X_FACTORS = {
    2: 16, 3: 3, 7573: 1, 26717: 1, 20551073: 1, 5325997: 1,
    131067902663: 1, 1034162957: 1, 54365020012269253057: 1,
    6108168573339184993184552423703437623: 1,
    510235133874300723558753957808053209: 1,
}

def generate_divisors(factors):
    primes = sorted(factors.keys())
    exp_ranges = [range(factors[p] + 1) for p in primes]
    divs = []
    for exps in product(*exp_ranges):
        v = 1
        for p, eexp in zip(primes, exps):
            if eexp:
                v *= p**eexp
        divs.append(v)
    return sorted(divs)

divs = generate_divisors(X_FACTORS)                  # 34 816 dělitelů
primes_p = [d + 1 for d in divs if isPrime(d + 1)]   # 660 kandidátních prvočísel

for p, q in combinations_with_replacement(primes_p, 2):
    n = p * q
    if n <= c:
        continue
    k = (n.bit_length() + 7) // 8
    m = pow(c, d, n)
    em = m.to_bytes(k, "big")          # pevná délka, zachová úvodní nuly!
    if b"HCKR{" in em:
        print(em)                      # nalezena vlajka
        break
```

### Výstup

```
HCKR{S4M0zr3jMe_z3_N_j1m_ScH0v4L4_EV4}
```
</content>
