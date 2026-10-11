"""
Ale ne! Alice a Bob si hráli s RSA, ale bohužel ztratili modul a nyní nemohou dešifrovat jejich zprávu. Pomůžeš jim najít ztracený modul a dešifrovat tak zprávu?

    Veřejný exponent: 65537
    Soukromý exponent: 13732020974556595981129643152379568337833162459237646942961543641211348147598702041965557184544837721933671794341920150450664179941113857
    Zašifrovaná zpráva: 0x33743816105f6f521b7e618f7bef65a35a90dcba800cdbc7419c12965abc433081646c515c0af14c55a35a5debb60a275d228397ce1179927

Vlajka je ve formátu HCKR{...}.
"""

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

divs = generate_divisors(X_FACTORS)                  # 34,816 divisors
primes_p = [d + 1 for d in divs if isPrime(d + 1)]   # 660 prime candidates

for p, q in combinations_with_replacement(primes_p, 2):
    n = p * q
    if n <= c:
        continue
    k = (n.bit_length() + 7) // 8
    m = pow(c, d, n)
    em = m.to_bytes(k, "big")          # fixed-length, keeps leading zeros!
    if b"HCKR{" in em:
        print(em)                      # flag found
        break
