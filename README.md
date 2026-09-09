# @guardbee/mcp-dns-intelligence

[![npm version](https://img.shields.io/npm/v/@guardbee/mcp-dns-intelligence.svg)](https://www.npmjs.com/package/@guardbee/mcp-dns-intelligence)
[![npm downloads](https://img.shields.io/npm/dm/@guardbee/mcp-dns-intelligence.svg)](https://www.npmjs.com/package/@guardbee/mcp-dns-intelligence)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

DNS kayıtlarını sıralayan, SPF / DMARC / DKIM yapılandırma hatalarını tespit eden ve asılı (dangling) subdomain'leri bulan MCP sunucusu. Node.js yerleşik `dns/promises` kullanır — harici bağımlılık yoktur.

---

## Özellikler

- **Tam DNS Sıralaması** — A, AAAA, MX, NS, TXT, CNAME, SOA kayıtları
- **SPF Analizi** — `+all`, `?all`, fazla DNS sorgusu, yinelenen kayıt tespiti
- **DMARC Analizi** — Politika (`none`/`quarantine`/`reject`), `pct`, `rua` adresi eksikliği
- **DKIM Kontrolü** — 9 yaygın seçici probu (`default`, `google`, `selector1`, `mail`, vb.)
- **Subdomain Sıralaması** — 60+ yaygın alt alan; asılı CNAME tespiti (14 bulut sağlayıcısı)
- **E-posta Güvenliği Özeti** — SPF + DMARC + DKIM birleşik analizi ve kopyalanabilir düzeltme önerileri
- **23 Unit Test** — Ağ bağlantısı gerektirmeyen saf mantık testleri

---

## Hızlı Başlangıç

```bash
npm install -g @guardbee/mcp-dns-intelligence
```

`claude_desktop_config.json` dosyasına ekleyin:

```json
{
  "mcpServers": {
    "guardbee-dns-intelligence": {
      "command": "npx",
      "args": ["-y", "@guardbee/mcp-dns-intelligence"]
    }
  }
}
```

---

## MCP Tools

| Tool | Açıklama |
|------|----------|
| `enumerate_dns` | Domain için tüm DNS kayıtlarını sıralar ve SPF/DMARC/DKIM analizi yapar |
| `enumerate_subdomains` | Yaygın subdomain'leri dener; asılı CNAME'leri işaretler |
| `check_email_security` | SPF + DMARC + DKIM birleşik denetimi ve düzeltme önerileri |
| `lookup_dns` | Belirli bir kayıt türü için hedefli DNS sorgusu (A/MX/TXT/vb.) |

### Örnek Kullanım

Claude'a şunu sorabilirsiniz:

> "example.com'un DNS yapılandırmasında sorun var mı?"

> "example.com'un e-posta güvenliğini denetle — SPF, DMARC ve DKIM"

> "example.com'un subdomain'lerini listele, asılı olanları işaretle"

> "example.com'un MX kayıtları neler?"

### Örnek Çıktı

```
Email Security Check: example.com
──────────────────────────────────────────────────

── SPF ─────────────────────────────────────────
✓ v=spf1 include:_spf.google.com -all

── DMARC ───────────────────────────────────────
✗ No DMARC record found at _dmarc.example.com
  Add:  v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com

── DKIM ────────────────────────────────────────
✓ Found DKIM selectors: google
```

---

## SPF Bulguları

| Kod | Severity | Açıklama |
|-----|----------|----------|
| `SPF_MISSING` | 🟡 Medium | SPF kaydı bulunamadı |
| `SPF_PERMISSIVE_ALL` | 🔴 Critical | `+all` — her sunucuya izin veriyor |
| `SPF_NEUTRAL_ALL` | 🟠 High | `?all` — yetkisiz gönderenleri reddetmiyor |
| `SPF_NO_ALL` | 🟡 Medium | `all` mekanizması yok |
| `SPF_TOO_MANY_LOOKUPS` | 🟠 High | > 10 DNS sorgusu — SPF hatasına yol açar |
| `SPF_DUPLICATE` | 🟠 High | Birden fazla SPF kaydı |

## DMARC Bulguları

| Kod | Severity | Açıklama |
|-----|----------|----------|
| `DMARC_MISSING` | 🟠 High | DMARC kaydı yok |
| `DMARC_NO_POLICY` | 🟠 High | `p=` politikası eksik |
| `DMARC_POLICY_NONE` | 🟡 Medium | `p=none` — izleme modu, engelleme yok |
| `DMARC_PCT_LOW` | 🔵 Low | `pct` < 100 — kısmi uygulama |
| `DMARC_NO_RUA` | 🔵 Low | Toplu rapor adresi (`rua`) yok |

## Asılı Subdomain Tespiti

CNAME'i aşağıdaki sağlayıcılardan birine işaret edip çözümlenemeyen subdomain'ler **asılı (dangling)** olarak işaretlenir ve subdomain ele geçirme riski taşır:

AWS S3, Azure App Service, GitHub Pages, Heroku, Netlify, Vercel, Cloudflare Pages, Surge, Pantheon, WP Engine, Ghost, Shopify, Fastly, AWS CloudFront

---

## CLI — CI/CD Entegrasyonu

MCP server moduna ek olarak doğrudan CLI olarak da kullanılabilir:

```bash
# Tam DNS + e-posta güvenliği kontrolü
npx @guardbee/mcp-dns-intelligence check example.com

# Sadece high ve üstünde başarısız ol
npx @guardbee/mcp-dns-intelligence check example.com --fail-on=high

# Subdomain taraması — dangling CNAME varsa exit 1
npx @guardbee/mcp-dns-intelligence subdomains example.com

# Yüksek concurrency ile subdomain tarama
npx @guardbee/mcp-dns-intelligence subdomains example.com --concurrency=50

# JSON çıktı
npx @guardbee/mcp-dns-intelligence check example.com --format=json
```

**Exit kodları:** `0` = sorun yok · `1` = threshold üstü bulgu / dangling subdomain · `2` = hata

### GitHub Actions — DNS Güvenlik Denetimi

```yaml
name: DNS Security Check
on:
  schedule:
    - cron: "0 6 * * *"  # Her gün 06:00
  workflow_dispatch:

jobs:
  dns-check:
    runs-on: ubuntu-latest
    steps:
      - name: Check DNS configuration
        run: npx @guardbee/mcp-dns-intelligence check ${{ vars.DOMAIN }} --fail-on=high

      - name: Scan for dangling subdomains
        run: npx @guardbee/mcp-dns-intelligence subdomains ${{ vars.DOMAIN }}
```

### GitLab CI

```yaml
dns-security:
  image: node:20
  script:
    - npx @guardbee/mcp-dns-intelligence check $DOMAIN --fail-on=high
    - npx @guardbee/mcp-dns-intelligence subdomains $DOMAIN
  only:
    - schedules
```

### Deployment Öncesi E-posta Güvenliği Kontrolü

```yaml
- name: Verify email security records
  run: |
    npx @guardbee/mcp-dns-intelligence check ${{ vars.DOMAIN }} \
      --fail-on=high \
      --format=json | tee dns-report.json

- name: Upload DNS report
  uses: actions/upload-artifact@v4
  with:
    name: dns-security-report
    path: dns-report.json
```

---

## Geliştirme

```bash
npm install
npm test          # 23 unit test
npm run build     # TypeScript derleme
```

---

## Lisans

MIT — [GuardBee](https://guardbee.ai)
