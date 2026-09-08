"""The outreach console's HTML, self-contained.

Loads nothing from the network — no fonts, no scripts, no stylesheets — so it
works on a laptop with only the tailnet up, and it cannot leak a referrer for
a domain being investigated.

Design note, so the next edit does not flatten it: the page is deliberately
two instruments side by side. The left panel reads like a zone file, because
that is literally what it is showing (public DNS records, monospaced, one per
line, verdict in a gutter you can scan vertically). The right panel is prose,
set in the body face, because that side writes to a human being. Colour is
never decorative: three verdict colours, plus one cyan reserved exclusively
for things you can act on.
"""

PAGE = r"""<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>Vigía · consola privada</title>
<style>
  :root {
    /* Ground is blue-hued on purpose, not near-black. */
    --void:    #0a0f18;
    --zone:    #0d131e;   /* left panel: the machine side */
    --desk:    #141a25;   /* right panel: the human side  */
    --raised:  #1b2230;
    --line:    #212a38;
    --line-hi: #2d3849;

    --ink:     #e9eef6;
    --dim:     #93a0b4;
    --faint:   #5f6b7d;

    /* Verdicts. The only colours in the page besides --act. */
    --fail:    #ff5f52;
    --warn:    #e9a13b;
    --pass:    #3fbf8f;
    /* Interaction. If it is cyan, you can act on it. */
    --act:     #5ad2f0;

    --mono: ui-monospace, "SF Mono", SFMono-Regular, "JetBrains Mono", Menlo, Consolas, monospace;
    --sans: ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
  }

  * { box-sizing: border-box; }
  html { -webkit-text-size-adjust: 100%; }
  body {
    margin: 0;
    background: var(--void);
    color: var(--ink);
    font: 14.5px/1.6 var(--sans);
    -webkit-font-smoothing: antialiased;
  }
  :focus-visible {
    outline: 2px solid var(--act);
    outline-offset: 2px;
    border-radius: 3px;
  }

  /* ---------------------------------------------------------- eyebrows */
  .eyebrow {
    font: 600 10px/1 var(--mono);
    letter-spacing: .18em;
    text-transform: uppercase;
    color: var(--faint);
  }

  /* ------------------------------------------------------------ header */
  .bar {
    position: sticky; top: 0; z-index: 20;
    display: flex; align-items: center; gap: 20px; flex-wrap: wrap;
    padding: 13px 24px;
    background: rgba(10,15,24,.86);
    backdrop-filter: blur(10px);
    border-bottom: 1px solid var(--line);
  }
  .mark { font: 600 14px/1 var(--sans); letter-spacing: .02em; }
  .mark b { color: var(--act); font-weight: 600; }
  .peer {
    font: 500 11px/1 var(--mono);
    color: var(--pass);
    display: inline-flex; align-items: center; gap: 7px;
  }
  .peer::before {
    content: ""; width: 6px; height: 6px; border-radius: 50%;
    background: var(--pass); box-shadow: 0 0 0 3px rgba(63,191,143,.18);
  }
  .peer.off { color: var(--fail); }
  .peer.off::before { background: var(--fail); box-shadow: 0 0 0 3px rgba(255,95,82,.18); }

  /* The stepper encodes a real interlock: each step is unreachable until
     the previous one has produced something. It is not ornament. */
  .steps { display: flex; align-items: center; gap: 2px; margin-left: auto; }
  .step {
    font: 500 10.5px/1 var(--mono); letter-spacing: .1em; text-transform: uppercase;
    color: var(--faint); padding: 5px 9px; border-radius: 5px; white-space: nowrap;
  }
  .step i { font-style: normal; opacity: .5; margin-right: 5px; }
  .step.on { color: var(--act); background: rgba(90,210,240,.09); }
  .step.on i { opacity: 1; }
  .step.done { color: var(--dim); }
  .step + .step::before { content: "→"; margin-right: 8px; color: var(--line-hi); }

  /* ------------------------------------------------------------ layout */
  .wrap {
    display: grid; gap: 1px;
    background: var(--line);
    grid-template-columns: minmax(0, 1.08fr) minmax(0, 1fr);
    align-items: start;
    min-height: calc(100vh - 53px);
  }
  .zone { background: var(--zone); padding: 26px 24px 40px; }
  .desk { background: var(--desk); padding: 26px 24px 40px; }
  @media (max-width: 1040px) {
    .wrap { grid-template-columns: 1fr; }
    .zone, .desk { padding: 22px 18px 32px; }
  }

  section + section { margin-top: 30px; }
  .head { display: flex; align-items: baseline; gap: 11px; margin-bottom: 5px; }
  .head h2 { margin: 0; font: 600 15px/1.3 var(--sans); letter-spacing: .01em; }
  .head .n {
    font: 600 10px/1 var(--mono); color: var(--act);
    border: 1px solid var(--line-hi); border-radius: 4px; padding: 4px 6px;
  }
  .lede { margin: 0 0 15px; color: var(--dim); font-size: 13px; max-width: 62ch; }

  /* ------------------------------------------------------------ fields */
  label.f { display: block; margin: 16px 0 6px; }
  textarea, input[type=text] {
    width: 100%; display: block;
    background: var(--void); color: var(--ink);
    border: 1px solid var(--line-hi); border-radius: 8px;
    padding: 11px 12px;
    font: 14px/1.65 var(--mono);
    resize: vertical;
    transition: border-color .15s ease;
  }
  textarea::placeholder { color: var(--faint); }
  textarea:hover, input[type=text]:hover { border-color: #3a465c; }
  textarea.prose { font-family: var(--sans); font-size: 14px; }

  .actions { display: flex; align-items: center; gap: 11px; flex-wrap: wrap; margin-top: 12px; }
  .count { font: 500 11.5px/1 var(--mono); color: var(--faint); letter-spacing: .04em; }
  kbd {
    font: 500 10.5px/1 var(--mono); color: var(--faint);
    border: 1px solid var(--line-hi); border-bottom-width: 2px;
    border-radius: 4px; padding: 3px 5px;
  }

  button {
    font: 600 13px/1 var(--sans); letter-spacing: .01em;
    border: 1px solid transparent; border-radius: 8px;
    padding: 10px 15px; cursor: pointer;
    background: var(--act); color: #04121a;
    transition: filter .15s ease, opacity .15s ease;
  }
  button:hover:not(:disabled) { filter: brightness(1.12); }
  button.quiet { background: transparent; border-color: var(--line-hi); color: var(--ink); font-weight: 500; }
  button.quiet:hover:not(:disabled) { border-color: var(--act); color: var(--act); filter: none; }
  button.arm { background: var(--warn); color: #1a1204; }
  button:disabled { opacity: .38; cursor: not-allowed; }
  button[aria-busy=true] { cursor: progress; }

  /* -------------------------------------------------- the posture strip
     Six mechanisms, fixed order, always all six. Scanning the strip down a
     column of domains compares their posture without reading a word. */
  .posture { display: flex; gap: 3px; margin: 2px 0 14px; }
  .seg { flex: 1; min-width: 0; }
  .seg .k {
    display: block; font: 600 8.5px/1 var(--mono); letter-spacing: .1em;
    color: var(--faint); margin-bottom: 5px; white-space: nowrap; overflow: hidden;
  }
  .seg .v {
    display: block; height: 4px; border-radius: 2px; background: var(--line-hi);
    transform-origin: left center;
  }
  .seg[data-v=fail] .v { background: var(--fail); }
  .seg[data-v=warn] .v { background: var(--warn); }
  .seg[data-v=pass] .v { background: var(--pass); }
  .seg[data-v=fail] .k, .seg[data-v=warn] .k { color: var(--dim); }
  @media (prefers-reduced-motion: no-preference) {
    .lit .seg .v { animation: fill .34s cubic-bezier(.2,.7,.3,1) both; }
    .lit .seg:nth-child(1) .v { animation-delay: .00s }
    .lit .seg:nth-child(2) .v { animation-delay: .05s }
    .lit .seg:nth-child(3) .v { animation-delay: .10s }
    .lit .seg:nth-child(4) .v { animation-delay: .15s }
    .lit .seg:nth-child(5) .v { animation-delay: .20s }
    .lit .seg:nth-child(6) .v { animation-delay: .25s }
    @keyframes fill { from { transform: scaleX(0); opacity: 0 } to { transform: scaleX(1); opacity: 1 } }
  }

  /* ------------------------------------------------------------ records */
  .domain { padding: 18px 0 4px; border-top: 1px solid var(--line); }
  .domain:first-of-type { border-top: 0; padding-top: 8px; }
  .dname {
    font: 400 25px/1.15 var(--mono); letter-spacing: -.015em;
    word-break: break-all; margin: 0 0 4px;
  }
  .dname .dot { color: var(--faint); }        /* labels read as hierarchy */
  .dmeta { font: 500 11px/1 var(--mono); color: var(--faint); letter-spacing: .05em; margin-bottom: 13px; }

  .rec { display: grid; grid-template-columns: 18px 1fr; gap: 0 10px; padding: 9px 0; border-top: 1px dashed var(--line); }
  .rec:first-of-type { border-top: 0; }
  .g { font: 600 14px/1.45 var(--mono); text-align: center; }
  .rec[data-v=fail] .g { color: var(--fail); }
  .rec[data-v=warn] .g { color: var(--warn); }
  .rec .t { font: 600 13px/1.45 var(--sans); }
  .rec .s { color: var(--dim); font-size: 13px; margin-top: 2px; }
  .rec .i { color: var(--dim); font: 12.5px/1.55 var(--mono); margin-top: 4px; }
  .rec .i b { color: var(--warn); font-weight: 600; }
  details.fix { margin-top: 6px; }
  details.fix summary {
    font: 500 12px/1 var(--sans); color: var(--act);
    cursor: pointer; list-style: none; display: inline-flex; gap: 6px; align-items: center;
  }
  details.fix summary::-webkit-details-marker { display: none; }
  details.fix summary::before { content: "+"; font: 600 13px/1 var(--mono); }
  details.fix[open] summary::before { content: "−"; }
  details.fix p { margin: 7px 0 0; color: var(--dim); font-size: 12.5px; max-width: 66ch; }

  .clean { color: var(--pass); font: 500 13px/1.5 var(--sans); }

  /* ------------------------------------------------------------- empty */
  .empty { border: 1px dashed var(--line-hi); border-radius: 10px; padding: 28px 22px; }
  .empty p { margin: 0; color: var(--dim); font-size: 13px; max-width: 52ch; }
  .empty .z { font: 12.5px/1.9 var(--mono); color: var(--faint); margin-bottom: 14px; white-space: pre; }

  /* -------------------------------------------------------- recipients */
  .chips { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 9px; min-height: 1px; }
  .chip {
    font: 500 12px/1 var(--mono); color: var(--act);
    background: rgba(90,210,240,.08); border: 1px solid rgba(90,210,240,.3);
    border-radius: 999px; padding: 5px 9px;
  }
  .known { margin-top: 9px; border: 1px solid var(--line); border-radius: 9px; overflow: hidden; }
  .known .row {
    display: flex; align-items: center; gap: 10px; padding: 9px 12px;
    border-top: 1px solid var(--line); cursor: pointer;
  }
  .known .row:first-child { border-top: 0; }
  .known .row:hover { background: var(--raised); }
  .known input { accent-color: var(--act); width: 15px; height: 15px; flex: none; }
  .known .em { font: 13px/1.3 var(--mono); flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; }
  .known .tag { font: 500 10px/1 var(--mono); letter-spacing: .08em; color: var(--faint); text-transform: uppercase; }
  .known .none { padding: 13px; color: var(--faint); font-size: 13px; }

  /* ------------------------------------------------------------ letter */
  .letter { border: 1px solid var(--line-hi); border-radius: 10px; overflow: hidden; background: var(--void); }
  .letter .hd { padding: 12px 14px; border-bottom: 1px solid var(--line); display: grid; gap: 5px; }
  .letter .hd div { display: flex; gap: 10px; font-size: 13px; align-items: baseline; }
  .letter .hd span {
    font: 600 9.5px/1.5 var(--mono); letter-spacing: .12em; text-transform: uppercase;
    color: var(--faint); width: 48px; flex: none;
  }
  .letter .hd em { font-style: normal; color: var(--ink); min-width: 0; word-break: break-word; }
  .letter .bd {
    padding: 14px; margin: 0; max-height: 380px; overflow: auto;
    font: 12.5px/1.7 var(--mono); color: var(--dim);
    white-space: pre-wrap; word-break: break-word;
  }

  /* ------------------------------------------------------------- notes */
  .say { margin-top: 13px; padding: 11px 13px; border-radius: 8px; font-size: 13px; border: 1px solid; }
  .say.err  { background: rgba(255,95,82,.09);  border-color: rgba(255,95,82,.38);  color: #ffb3ad; }
  .say.good { background: rgba(63,191,143,.09); border-color: rgba(63,191,143,.38); color: #8fe3c4; }
  .say.work { background: var(--raised); border-color: var(--line-hi); color: var(--dim); }
  .say b { color: var(--ink); }

  .caution {
    margin-top: 16px; padding-left: 13px; border-left: 2px solid var(--warn);
    color: var(--dim); font-size: 12.5px; max-width: 60ch;
  }
  .caution b { color: var(--warn); font-weight: 600; }
  .caution + .caution { margin-top: 11px; }

  .toggle { display: flex; align-items: flex-start; gap: 9px; margin-top: 14px; cursor: pointer; }
  .toggle input { accent-color: var(--warn); width: 15px; height: 15px; margin-top: 2px; flex: none; }
  .toggle span { font-size: 12.5px; color: var(--dim); }
  .toggle b { color: var(--ink); font-weight: 600; display: block; font-size: 13px; }

  /* --------------------------------------------------------------- log */
  .ledger { border-top: 1px solid var(--line); background: var(--zone); padding: 20px 24px 44px; }
  .ledger summary {
    cursor: pointer; list-style: none; display: flex; align-items: center; gap: 10px;
  }
  .ledger summary::-webkit-details-marker { display: none; }
  .ledger summary::before { content: "▸"; color: var(--act); font-size: 11px; }
  .ledger[open] summary::before { content: "▾"; }
  table { width: 100%; border-collapse: collapse; margin-top: 15px; }
  th {
    text-align: left; padding: 0 12px 8px 0; border-bottom: 1px solid var(--line);
    font: 600 9.5px/1 var(--mono); letter-spacing: .12em; text-transform: uppercase; color: var(--faint);
  }
  td { padding: 10px 12px 10px 0; border-bottom: 1px solid var(--line); font-size: 13px; vertical-align: top; }
  td.m { font-family: var(--mono); font-size: 12.5px; }
  td.when { color: var(--faint); font: 12px/1.5 var(--mono); white-space: nowrap; }
  .verdict { font: 600 11px/1 var(--mono); letter-spacing: .06em; text-transform: uppercase; }
  .verdict.ok { color: var(--pass); }
  .verdict.no { color: var(--fail); }
  .why { color: var(--faint); font: 12px/1.5 var(--mono); margin-top: 4px; }
  .ledger .none { color: var(--faint); font-size: 13px; padding: 16px 0 0; }
</style>
</head>
<body>

<div class="bar">
  <span class="mark">VIG<b>Í</b>A · consola privada</span>
  <span class="peer" id="peer">comprobando red…</span>
  <nav class="steps" aria-label="Progreso">
    <span class="step on"  id="s1"><i>1</i>Consulta</span>
    <span class="step"     id="s2"><i>2</i>Destinatarios</span>
    <span class="step"     id="s3"><i>3</i>Envío</span>
  </nav>
</div>

<div class="wrap">

  <!-- ============================ the machine side ============================ -->
  <div class="zone">
    <section>
      <div class="head"><span class="n">1</span><h2>Consulta de registros</h2></div>
      <p class="lede">Un dominio por línea. Se resuelven SPF, DKIM, DMARC, MTA-STS,
        TLS-RPT y DNSSEC en el DNS público. No se toca ningún sistema del dominio ni
        se le envía correo.</p>
      <label class="f eyebrow" for="domains">Dominios</label>
      <textarea id="domains" rows="4" spellcheck="false" autocapitalize="off"
        placeholder="ejemplo.com&#10;otraempresa.es"></textarea>
      <div class="actions">
        <button id="btn-check">Consultar DNS</button>
        <span class="count" id="count">0 dominios</span>
        <kbd>⌘ ⏎</kbd>
      </div>
      <div id="say-check" hidden></div>
    </section>

    <section id="out" aria-live="polite">
      <div class="empty">
        <div class="z">;; ANSWER SECTION
;; (a la espera de una consulta)</div>
        <p>Escribe un dominio y consulta sus registros. Nada sale de aquí hasta que
          leas el texto que se va a enviar.</p>
      </div>
    </section>
  </div>

  <!-- ============================= the human side ============================= -->
  <div class="desk">
    <section>
      <div class="head"><span class="n">2</span><h2>Destinatarios</h2></div>
      <p class="lede">Escribe las direcciones a mano, o elige entre quienes ya usan
        Vigía.</p>
      <label class="f eyebrow" for="to">A mano · una por línea</label>
      <textarea id="to" rows="2" spellcheck="false" autocapitalize="off"
        placeholder="seguridad@ejemplo.com"></textarea>
      <label class="f eyebrow">Registradas en Vigía</label>
      <div class="known" id="known"><div class="none">Cargando…</div></div>
      <div class="chips" id="chips"></div>
      <label class="f eyebrow" for="note">Nota personal · encabeza el mensaje</label>
      <textarea id="note" class="prose" rows="3"
        placeholder="Nos vimos en la conferencia de la semana pasada…"></textarea>
    </section>

    <section>
      <div class="head"><span class="n">3</span><h2>Revisión y envío</h2></div>
      <p class="lede">Lee el texto antes de enviarlo. Es literalmente lo que va a
        recibir la otra persona.</p>
      <div class="actions">
        <button id="btn-preview" class="quiet" disabled>Ver el texto</button>
        <button id="btn-send" disabled>Enviar</button>
      </div>
      <div id="say-send" hidden></div>
      <div id="letter"></div>

      <label class="toggle">
        <input type="checkbox" id="force">
        <span><b>Escribir de nuevo a quien ya recibió un mensaje</b>
          Sin esto, una dirección contactada en los últimos 14 días se rechaza.</span>
      </label>

      <p class="caution"><b>Sale desde tu dominio.</b> Es el mismo con el que publicas
        Butaca, PrepDesk y el PDF. Una marca de spam daña la reputación de todos.</p>
      <p class="caution"><b>No verías el daño.</b> Tus informes DMARC van hoy a un
        tercero, así que cambia el <span style="font-family:var(--mono)">rua</span>
        antes de escribir a desconocidos.</p>
    </section>
  </div>
</div>

<details class="ledger" id="ledger">
  <summary><span class="eyebrow">Envíos</span><span class="count" id="log-count"></span></summary>
  <table>
    <thead><tr><th>Cuándo</th><th>Destinatario</th><th>Dominios</th><th>Hallazgos</th><th>Resultado</th></tr></thead>
    <tbody id="log"></tbody>
  </table>
  <div class="none" id="log-none" hidden>Todavía no se ha enviado nada.</div>
</details>

<script>
"use strict";
const $ = (id) => document.getElementById(id);

/* Absolute base: the console answers at /tailnet and /tailnet/, and a
   relative "api/..." would resolve to /api/... on the first of those. */
const API = location.pathname.replace(/\/?$/, "/") + "api/";

const MECHS = [
  ["spf", "SPF"], ["dkim", "DKIM"], ["dmarc", "DMARC"],
  ["mta_sts", "STS"], ["tls_rpt", "RPT"], ["dnssec", "SEC"],
];
const GLYPH = { fail: "✗", warn: "!", pass: "·" };

let checked = [];        // domains whose records are on screen
let previewed = false;   // the interlock: no send without reading the text

const esc = (s) => String(s == null ? "" : s).replace(/[&<>"]/g,
  (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

async function api(path, body) {
  const res = await fetch(API + path, body ? {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  } : {});
  return { ok: res.ok, status: res.status, data: await res.json().catch(() => ({})) };
}

function say(where, text, kind) {
  const box = $(where);
  box.hidden = false;
  box.className = "say " + kind;
  box.innerHTML = text;
}
const hush = (where) => { $(where).hidden = true; };

function busy(button, on, label) {
  button.setAttribute("aria-busy", on ? "true" : "false");
  button.disabled = on;
  if (label !== undefined) button.textContent = label;
}

/* ------------------------------------------------------------ recipients */

function chosen() {
  const typed = $("to").value.replace(/,/g, "\n").split("\n");
  const ticked = [...document.querySelectorAll(".known input:checked")].map((i) => i.value);
  const all = [...typed, ...ticked].map((s) => s.trim()).filter(Boolean);
  return [...new Set(all)];
}

function paintChips() {
  const list = chosen();
  $("chips").innerHTML = list.map((e) => `<span class="chip">${esc(e)}</span>`).join("");
  syncSteps();
  return list;
}

/* ------------------------------------------------------------- the steps */

function syncSteps() {
  const has = { 1: checked.length > 0, 2: chosen().length > 0, 3: previewed };
  const active = !has[1] ? 1 : !has[2] ? 2 : 3;
  [1, 2, 3].forEach((n) => {
    const el = $("s" + n);
    el.className = "step" + (n === active ? " on" : has[n] ? " done" : "");
  });
  $("btn-preview").disabled = !has[1];
  const ready = has[1] && has[2] && previewed;
  const send = $("btn-send");
  send.disabled = !ready;
  if (!ready || send.dataset.armed !== "1") {
    send.className = "";
    send.textContent = has[2] ? `Enviar a ${chosen().length}` : "Enviar";
    delete send.dataset.armed;
  }
}

/* ------------------------------------------------------------------ boot */

async function boot() {
  const { data } = await api("whoami");
  const peer = $("peer");
  if (!data.allowed) {
    peer.className = "peer off";
    peer.textContent = "sin acceso";
    say("say-check", `<b>Fuera del tailnet.</b> ${esc(data.reason)}.
      Abre esta página desde una máquina de tu red Tailscale.`, "err");
    document.querySelectorAll("button, textarea, input").forEach((c) => (c.disabled = true));
    return;
  }
  peer.textContent = data.peer;

  const { data: r } = await api("recipients");
  const people = r.recipients || [];
  $("known").innerHTML = people.length
    ? people.map((p) => `<label class="row">
        <input type="checkbox" value="${esc(p.email)}">
        <span class="em">${esc(p.email)}</span>
        <span class="tag">${esc(p.org)} · ${esc(p.kind)}</span></label>`).join("")
    : `<div class="none">Ninguna organización conectada todavía.</div>`;
  document.querySelectorAll(".known input").forEach((i) => (i.onchange = paintChips));
  loadLog();
}

/* ----------------------------------------------------------- the records */

const prettyDomain = (d) =>
  esc(d).split(".").join('<span class="dot">.</span>');

function renderDomain(domain, report, problems) {
  const status = (key) => {
    const part = report ? report[key] : null;
    return part && part.status ? part.status : "";
  };
  const strip = MECHS.map(([key, label]) =>
    `<div class="seg" data-v="${esc(status(key))}" title="${esc(label)}: ${esc(status(key) || "sin dato")}">
       <span class="k">${label}</span><span class="v"></span></div>`).join("");

  const provider = report && report.mx && report.mx.provider ? report.mx.provider : "";
  const meta = [
    `${problems.length} de 6 mecanismos a revisar`,
    provider ? `correo: ${provider}` : "",
  ].filter(Boolean).join("  ·  ");

  const rows = problems.length
    ? problems.map((p) => `<div class="rec" data-v="${esc(p.status)}">
        <div class="g">${GLYPH[p.status] || "·"}</div>
        <div>
          <div class="t">${esc(p.label)}</div>
          <div class="s">${esc(p.summary)}</div>
          ${p.issues.map((i) => `<div class="i">${esc(i)}</div>`).join("")}
          ${p.fix ? `<details class="fix"><summary>Cómo se arregla</summary>
            <p>${esc(p.fix)}</p></details>` : ""}
        </div></div>`).join("")
    : `<p class="clean">${GLYPH.pass} Los seis mecanismos están en orden. No hay nada
        que contarle a este dominio.</p>`;

  return `<article class="domain">
      <h3 class="dname">${prettyDomain(domain)}</h3>
      <div class="posture lit">${strip}</div>
      <div class="dmeta">${esc(meta)}</div>
      ${rows}
    </article>`;
}

$("btn-check").onclick = async () => {
  const button = $("btn-check");
  busy(button, true, "Resolviendo…");
  say("say-check", "Consultando el DNS público…", "work");

  const { ok, data } = await api("check", { domains: $("domains").value });
  busy(button, false, "Consultar DNS");

  if (!ok) {
    checked = [];
    syncSteps();
    say("say-check", `<b>No se ha consultado nada.</b> ${esc(data.message || "Error")}`, "err");
    return;
  }

  hush("say-check");
  const byName = {};
  (data.reports || []).forEach((r) => (byName[r.domain] = r));
  checked = data.summary.domains;
  previewed = false;
  $("letter").innerHTML = "";
  hush("say-send");

  $("out").innerHTML = checked
    .map((d) => renderDomain(d, byName[d], data.problems[d] || []))
    .join("");

  const s = data.summary;
  $("count").textContent =
    `${s.domains.length} ${s.domains.length === 1 ? "dominio" : "dominios"} · ` +
    `${s.fail} problema${s.fail === 1 ? "" : "s"} · ${s.warn} aviso${s.warn === 1 ? "" : "s"}`;
  syncSteps();
};

$("domains").oninput = () => {
  const n = $("domains").value.split(/[\n,]/).map((s) => s.trim()).filter(Boolean).length;
  $("count").textContent = `${n} ${n === 1 ? "dominio" : "dominios"}`;
};
$("domains").onkeydown = (e) => {
  if ((e.metaKey || e.ctrlKey) && e.key === "Enter") { e.preventDefault(); $("btn-check").click(); }
};
$("to").oninput = paintChips;

/* ------------------------------------------------------------ the letter */

$("btn-preview").onclick = async () => {
  const button = $("btn-preview");
  busy(button, true, "Componiendo…");
  const { ok, data } = await api("preview", {
    domains: $("domains").value, note: $("note").value,
  });
  busy(button, false, "Ver el texto");

  if (!ok) { say("say-send", `<b>Sin texto.</b> ${esc(data.message || "Error")}`, "err"); return; }

  const to = chosen();
  $("letter").innerHTML = `<div class="letter">
      <div class="hd">
        <div><span>De</span><em>${esc(data.from)}</em></div>
        <div><span>A</span><em>${to.length ? esc(to.join(", ")) : "— elige destinatarios —"}</em></div>
        <div><span>Asunto</span><em>${esc(data.subject)}</em></div>
      </div>
      <pre class="bd">${esc(data.body)}</pre>
    </div>`;
  previewed = true;
  hush("say-send");
  syncSteps();
};

$("btn-send").onclick = async () => {
  const button = $("btn-send");
  const to = chosen();

  /* Two steps, in place. A browser confirm() is easy to dismiss by reflex;
     changing the button to a warning colour is not. */
  if (button.dataset.armed !== "1") {
    button.dataset.armed = "1";
    button.className = "arm";
    button.textContent = `Confirmar envío a ${to.length}`;
    say("say-send", `Se enviará a <b>${esc(to.join(", "))}</b>. Pulsa otra vez para enviar.`, "work");
    return;
  }

  busy(button, true, "Enviando…");
  const { ok, data } = await api("send", {
    domains: $("domains").value, note: $("note").value,
    to: to.join("\n"), force: $("force").checked,
  });
  delete button.dataset.armed;
  busy(button, false);

  if (!ok) {
    say("say-send", `<b>No se ha enviado.</b> ${esc(data.message || "Error")}`, "err");
    syncSteps();
    return;
  }

  const failed = (data.results || []).filter((r) => !r.ok);
  const sent = data.results.length - failed.length;
  say("say-send", failed.length
      ? `Enviado a ${sent}. <b>Falló ${failed.length}:</b> ` +
        failed.map((f) => `${esc(f.to)} — ${esc(f.error)}`).join("; ")
      : `<b>Enviado a ${sent} ${sent === 1 ? "destinatario" : "destinatarios"}.</b>`,
    failed.length ? "err" : "good");

  previewed = false;
  syncSteps();
  loadLog();
};

/* --------------------------------------------------------------- the log */

function ago(iso) {
  const mins = Math.max(0, (Date.now() - new Date(iso).getTime()) / 6e4);
  if (mins < 1) return "ahora";
  if (mins < 60) return `hace ${Math.floor(mins)} min`;
  if (mins < 1440) return `hace ${Math.floor(mins / 60)} h`;
  return `hace ${Math.floor(mins / 1440)} d`;
}

async function loadLog() {
  const { data } = await api("log");
  const rows = data.sends || [];
  $("log-count").textContent = rows.length ? `${rows.length}` : "";
  $("log-none").hidden = rows.length > 0;
  $("log").innerHTML = rows.map((s) => `<tr>
      <td class="when" title="${esc(s.created_at)}">${ago(s.created_at)}</td>
      <td class="m">${esc(s.recipient)}</td>
      <td class="m">${esc(s.domains.join(", "))}</td>
      <td>${s.problems}</td>
      <td><span class="verdict ${s.ok ? "ok" : "no"}">${s.ok ? "enviado" : "falló"}</span>
        ${s.error ? `<div class="why">${esc(s.error)}</div>` : ""}</td>
    </tr>`).join("");
}

boot();
</script>
</body>
</html>
"""
