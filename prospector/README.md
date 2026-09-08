# Vigía — outreach

Turns Vigía's DNS scan output into individually reviewed outreach emails. It
prioritises one finding per domain, drafts a message around it, and puts it in a
queue that **a person has to approve** before anything leaves.

Internal tool. Served over Tailscale only, single user, no login beyond the
tailnet ACL.

**All five phases are built.** 300 tests, no test opens a socket.

---

## Read this before you send anything

**Your domain's reputation is the asset, and it is not recoverable.** A cold
domain that sends 200 messages on its first day gets its IP and its domain listed,
and then your ordinary business mail — invoices, replies to customers — starts
landing in spam too. That is not a marketing setback, it is an operational
failure of your main email address.

So:

- Warm up. Start at 5 messages a day and add 5 every two days. The default
  configuration does this; turning it off is a decision you should be able to
  justify.
- The daily cap is 40 by default. It is not a target to reach.
- Sends are spaced 90–180 seconds apart, randomised. A burst looks like a script,
  because it is one.
- If bounces go above a few per cent, stop. A high bounce rate is the single
  strongest signal to a receiver that the list was not consented to.
- Send to a domain **once**. A second unsolicited message to somebody who did not
  reply is what turns an unwanted email into a complaint.

---

## The legal constraints, and why they are in the code

This module writes unsolicited commercial email to Spanish and UK companies. That
is lawful under narrow conditions, and the conditions are enforced in the code
rather than left to the operator's memory.

**Role addresses only.** `info@`, `contacto@`, `sales@`. Writing to
`maria.gonzalez@empresa.es` processes a named person's data, and the
legitimate-interest balancing test that covers a message to a company does not
obviously cover a message to an individual. `addresses.py` classifies by
allowlist: an address is contactable only if it is *recognised* as a role address.
Anything else is refused — as `personal` when it matches a human-name shape, as
`unknown` when it is simply not recognised. Both are blocked; the distinction
exists so the review UI can let you take responsibility for an `unknown` and
never for a `personal`.

**Sender identification in every message.** Name, NIF or company number, postal
address. Spanish LSSI art. 10 and the GDPR's transparency duty both require it.
These are configuration values with no defaults, and the process **refuses to
start** without them.

**A one-click unsubscribe in every message**, with no login and no confirmation
page. One click, immediate, permanent.

**Suppression is permanent.** A domain or address on the list is never contacted
again, by any campaign, ever. This is enforced by database triggers that refuse
`DELETE` and `UPDATE` on the table, not by application code that remembers to
check — application code can be refactored around.

**The audit trail.** Every send records its legal basis and the specific finding
that made that domain relevant, per contact, per send. If somebody complains, the
answer to "why did you write to me" is a row, not a recollection.

**No tracking pixels.** Open tracking is off by default and there is a comment in
`config.py` explaining why: it processes personal data (IP, timestamp, mail
client) about somebody who never consented, for the purpose of measuring their
attention, which is considerably harder to defend as legitimate interest than the
message itself. The message has a case; watching whether they read it does not.

**Nothing sends itself.** Batch approval is fine. Silent auto-send is not, and
there is no code path that does it. A false positive sent to 200 companies cannot
be taken back.

---

## How to get in

Two processes, deliberately. The console is private; the unsubscribe link cannot be.

| | where | who reaches it |
|---|---|---|
| **Console** | `http://100.71.97.110:8116` | you, over Tailscale, and nothing else |
| **Unsubscribe** | `127.0.0.1:8123` → published as `https://diegofarina.com/baja/<token>` | the recipient, from the internet |

The recipient clicking the unsubscribe link is on the public internet, so a
tailnet-only endpoint would be a link that does not work in an email that legally
has to carry one that does. It is a **separate WSGI app with one acting route**, so
what gets published is that file and nothing else — no import screen, no queue, no
approve button can inherit public reach by accident.

### Before it starts

`.env` is written and has your SMTP (reused from Vigía) and your email. **Two lines
are blank and the service refuses to start until you fill them:**

```
PROSPECTOR_SENDER_NIF=
PROSPECTOR_SENDER_ADDRESS=
```

That refusal is the design, not an oversight. A commercial email without the
sender's name, company number and postal address is not badly formatted, it is
unlawful (LSSI art. 10 + GDPR), and I am not going to invent your NIF.

```bash
# rellena las dos líneas, luego:
systemctl --user enable --now prospector prospector-publico
```

To publish the unsubscribe link, the Funnel side:

```bash
tailscale funnel --bg --set-path=/baja 8123
```
…and the Cloudflare Worker needs `/baja` passed through, like `/vigia`.

### Then

Panel → **Importar** (CSV or a pasted list) → **Escanear y calificar** →
**Redactar borradores** → **Revisar** → approve → **Enviar los aprobados**.

In the review table: `a` approves, `s` skips, `e` opens the editor. Rows expand
with `<details>`, so the table works with JavaScript off; the keyboard handler is
the only script in the console.

## Layout

```
prospector/
  catalog.py     the six findings, ranked by commercial impact, ES + EN
  prioritise.py  select_primary_finding() — the one hook per domain
  qualify.py     commercial_score — is this prospect worth a send at all
  signals.py     what can be observed without contacting anybody, plus a fake
  addresses.py   role vs personal, allowlist, Spanish naming patterns
  db.py          schema, transactions, the suppression list
  config.py      settings, and the refusals at startup
  scanner.py     the boundary with Vigía's scanner, plus a fake for tests
  templates.py   the letters; renders completely or raises
  projection.py  rebuilding a finding from a stored scan
  pipeline.py    scan → qualify → record (touches nothing but public data)
  queue.py       draft → block-with-a-reason or queue-for-review
  sender.py      pre-send checks, warm-up, throttle, retries, bounces
  metrics.py     reply rate by finding type — the number that steers everything
  app.py         the console (tailnet only)
  unsubscribe.py the one public route
tests/           300 tests; none of them opens a socket
```

## Setup

Phase 1 has no dependencies beyond the standard library. `pytest` to run the
tests.

```bash
cd /home/diego/vigia/prospector
/home/diego/vigia/backend/.venv/bin/python -m pytest -q
```

Configuration is environment variables (see `config.py`). The ones without which
it will not start:

```bash
PROSPECTOR_BIND_HOST=100.71.97.110       # the tailscale0 address. Never 0.0.0.0.
PROSPECTOR_SENDER_NAME='...'
PROSPECTOR_SENDER_NIF='...'
PROSPECTOR_SENDER_ADDRESS='...'
PROSPECTOR_SENDER_EMAIL=diego@diegofarina.com
PROSPECTOR_UNSUBSCRIBE_BASE_URL='https://.../baja'

# opcional
PROSPECTOR_MIN_COMMERCIAL_SCORE=5   # por debajo, se escanea pero no se contacta
```

## The prioritisation order

Ranked by **commercial impact, not technical severity** — the two disagree, and
the disagreement is the point. Exactly one finding becomes the subject line.

| # | code | what the subject line says |
|---|------|----------------------------|
| 1 | `dmarc-missing` | anyone can send email as you |
| 2 | `spf-lookup-limit` | your SPF fails silently, mail goes to spam |
| 3 | `dkim-missing` | your email isn't signed |
| 4 | `spf-soft-all` | your policy permits spoofing |
| 5 | `dmarc-none-no-rua` | you have DMARC but you're not seeing the reports |
| 6 | `mta-sts-missing` | rarely the hook |

A domain with nothing on this list is **excluded**, not written to.

---

## Qualification: why the job is throwing prospects away

The prospect pool is effectively unlimited. Every domain with an MX record is a
technical candidate, and scanning costs nothing. **Sending is the bottleneck, and
what it consumes is not money — it is sender reputation and your name.** Neither
scales, and neither is recoverable.

Sending to 5,000 poorly-qualified domains destroys both: the bounces and
complaints get the domain listed, and the people who do read it see a message
that was obviously not written for them. Sending to 300 well-qualified ones with a
specific, true finding does not. So the qualification layer exists to
**deprioritise aggressively**, never to find more volume.

Each prospect gets a `commercial_score` from signals that cost nothing to gather —
public DNS and one homepage fetch. Nothing here involves contacting anybody.

| points | signal | why |
|---|---|---|
| +3 | ecommerce (Shopify/WooCommerce/PrestaShop fingerprints, checkout paths, payment provider in DNS) | revenue tied to email, cares today |
| +3 | high-value sector (legal, accounting, agencies, healthcare, logistics, B2B services) | holds client data, regulated, or runs on email |
| +2 | marketing platform in SPF (Mailchimp, SendGrid, Brevo, Klaviyo…) | already pays for deliverability, has a budget line |
| +2 | live website with a contact form | a way in |
| +1 | multiple MX records | somebody set mail up on purpose |
| −3 | no website resolving | |
| −5 | public administration domain | does not buy this |
| −5 | parked or for sale | nobody is home |

Only prospects at or above `PROSPECTOR_MIN_COMMERCIAL_SCORE` (default **5**) enter
the send queue. Everything else stays in the database, scanned and searchable, and
is simply never contacted. The default of 5 means a prospect needs a high-value
sector *or* a shop, plus at least one corroborating signal — not merely existing
and having a website.

The full breakdown is stored per prospect, not just the total. The threshold is a
business judgement that will get tuned, and tuning one number without seeing which
rules fired is guesswork.

**An unmeasured signal scores zero, never a penalty.** A domain whose site could
not be fetched is `unmeasured`, not `-3`. A qualification batch that hits a
network problem should qualify nobody, not silently bury everybody — the second
failure is permanent, because a prospect scored down during an outage never gets
looked at again.

**One known gap, left as specified.** −5 does not outweigh a full house of
positives, so a public body that *also* runs a shop (municipal ticketing, a museum
store) reaches 6 and qualifies. It needs every other signal to fire, so it is
narrow rather than a general leak, but it is real — and cold-emailing a town hall
is a bad look whatever the arithmetic says. The weights are as specified; the
consequence is pinned by `test_una_administracion_con_tienda_si_supera_el_umbral`
so that changing it means changing a test rather than quietly changing who gets
contacted. Say the word and it becomes a hard exclusion instead of a penalty.

---

### The rule that governs all of it

A finding fires only when the scanner can **assert** the fact, never when it
merely failed to establish it. `status == "undetermined"` is the absence of
evidence, not weak evidence.

This matters most for DKIM. Selectors cannot be enumerated, so a domain signing
with a selector nobody guessed looks identical to one that does not sign at all.
`dkim-missing` fires only when a selector the domain itself declared has no key at
it — and never when a wildcard TXT record makes every selector resolve. An email
telling a company their mail is unsigned when it is signed is the false positive
that costs you the domain.

---

## What was assumed about the scanner

Very little, in the end. The brief said to assume an interface and mock it; there
was no need, because `vigia.dns_email_auth.check_domain(domain, resolver, lang)`
already returns exactly the per-domain report this module needs. So
`scanner.ScannerPort` is written against the shape that function really returns,
and `scanner.build_report()` produces that same shape for tests. A mock built from
a guess would have passed Phase 1 and failed on contact with the real thing.

Three things are worth stating because they are judgements, not facts read off
the scanner:

1. **`resolver`.** `VigiaScanner` imports `vigia.dns_resolver.Resolver`. That
   import is lazy and untested here, because Phase 1 deliberately does not depend
   on Vigía being importable. It is the one line that will need checking when the
   two are wired together.

2. **MX absence.** The brief says to deprioritise domains with no MX because "they
   may not care". Implemented as specified, with one correction of fact: MX
   governs *inbound* mail, and a domain with no MX can still send (transactional
   domains do exactly that). So a missing MX is treated as a commercial signal —
   the finding is still real and still queued, just sorted last — rather than as a
   claim about whether they send mail. The single place it is treated as a hard
   fact is MTA-STS, which really is about inbound mail and nothing else: with no
   MX there is nothing to protect, so that finding is dropped rather than
   demoted.

3. **A failed MX lookup is not an absent MX.** A resolver timeout does not demote
   the domain. Otherwise a bad afternoon on the network quietly reclassifies half
   the list.

---

## Status

All five phases built and tested: data model and prioritisation, templates with
A/B variants, review queue and console, sender with warm-up and bounce handling,
metrics with CSV export. 300 tests.

Untested against the real world, and honestly so:

- **`HttpSignals`** (the homepage fetch behind the ecommerce and contact-form
  signals) is never exercised by the tests, which run without a network. Unverified
  until the first real batch.
- **`SmtpTransport`** has never opened a socket. The retry classification (4xx
  transient, 5xx permanent) is tested against fakes, not against a real MTA.
- **`VigiaScanner`** now imports the right class — `DnsResolverAdapter`, checked —
  but the two have not been run together end to end.

Send five to yourself before you send anything to a stranger.

This module supersedes the ad-hoc console at `backend/vigia/api/tailnet_routes.py`,
which sends one message at a time with no queue, no suppression list and no
unsubscribe link. That console should be retired once Phase 4 lands, not run
alongside this one — two senders sharing a domain reputation and not sharing a
suppression list is exactly how somebody gets contacted after asking not to be.
