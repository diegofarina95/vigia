/**
 * Layout regression check: nothing stacks letter-by-letter, nothing gets clipped.
 *
 *     npm run verify:layout                     # against the public URL
 *     VIGIA_URL=http://localhost:8110 npm run verify:layout
 *
 * Why this exists as a script and not a unit test: the bug it guards against is
 * only visible once a browser has laid the page out. A `flex` sibling marked
 * `shrink-0` with a long sentence inside it crushed the column next to it to 91px;
 * inside that column a `grid-cols-4` (which Tailwind compiles to
 * `minmax(0, 1fr)`, and that zero is the whole problem) let each cell reach 0px
 * wide, at which point "CRÍTICO" printed as a vertical column of seven letters.
 * Every class involved was individually reasonable and no assertion about the DOM
 * would have caught it.
 *
 * Two details that make it trustworthy:
 *
 *  · Lines are counted with `Range.getClientRects()`, which returns the real line
 *    boxes. Counting `scrollHeight / lineHeight` was the first attempt and it
 *    reported 28 false positives — padding inflates scrollHeight, and on SVG
 *    `<text>` it means nothing at all. Ranges spanning nested inline elements are
 *    skipped for the same reason: there the rects are one per inline box, not per
 *    line, which is what made a 2-line sentence read as 13.
 *
 *  · It INJECTS the long score-explanation sentence before measuring. The bug
 *    needed a tenant whose score had not moved while its findings had, so the demo
 *    data — which shows a 21-point drop and a short "▼ 21 respecto al anterior" —
 *    renders perfectly and proves nothing. The regression case has to be built.
 */
import { chromium } from "playwright-core";

const URL_BASE = process.env.VIGIA_URL || "https://diegofarina.com/vigia";

/** The real sentence, from `projection.py`, at its longest realistic length. */
const FRASE_LARGA =
  "3 cambios en tu organización, sin efecto en la puntuación";

const ANCHOS = [1440, 1280, 1024, 768, 390, 320];
const TEMAS = ["dark", "light"];

/** Runs in the page. Returns everything that stacks, clips or overflows.
 *
 * Two signals, kept separate because conflating them produced both false positives
 * and false negatives on the first two attempts:
 *
 *  1. A word split for no reason. Measured per WORD, not per text node: counting a
 *     node's line boxes flagged "brais.otero@agencia-exemplo.gal" because it starts
 *     mid-line after "conectado como" and wraps — two boxes, but no word broken.
 *     A single word owning more than one client rect is unambiguous.
 *
 *  2. A container crushed below what its own text needs. Necessary because signal 1
 *     stays silent exactly where the damage is worst: at 37px wide, "No verificado"
 *     has nowhere legal to break, so the split is "unavoidable" and the real defect
 *     is the 37px. This is the signal that catches the 0px severity cells.
 */
const DETECTAR = () => {
  const apilados = [];
  const estrujados = [];
  const cortados = [];

  const regla = document.createElement("span");
  regla.style.cssText = "position:absolute;visibility:hidden;white-space:pre;left:-9999px;top:0";
  document.body.appendChild(regla);
  const anchoDe = (texto, estilo) => {
    regla.style.font = estilo.font;
    regla.style.letterSpacing = estilo.letterSpacing;
    regla.textContent = texto;
    return regla.getBoundingClientRect().width;
  };

  const paseo = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
  for (let nodo = paseo.nextNode(); nodo; nodo = paseo.nextNode()) {
    const texto = (nodo.nodeValue || "");
    if (texto.trim().length < 2) continue;
    const padre = nodo.parentElement;
    if (!padre || padre.closest("svg") || padre === regla) continue;

    const estilo = getComputedStyle(padre);
    const caja = padre.getBoundingClientRect();
    // Not laid out at all — a collapsed panel, a `hidden` branch. Zero width there is
    // correct, and without this guard the zero-width rule below reported a button
    // inside a closed section as a crushed container on every single viewport.
    // Height is the liveness test, not width: a container crushed to 0px wide still
    // has a line's worth of height, which is exactly the case that must be caught.
    if (caja.height === 0) continue;
    const hueco = caja.width
      - parseFloat(estilo.paddingLeft || 0) - parseFloat(estilo.paddingRight || 0);

    // ── señal 1: alguna palabra partida pudiendo caber entera
    for (const m of texto.matchAll(/\S+/g)) {
      const palabra = m[0];
      if (palabra.length < 2) continue;
      const rango = document.createRange();
      rango.setStart(nodo, m.index);
      rango.setEnd(nodo, m.index + palabra.length);
      const cajas = [...rango.getClientRects()].filter((c) => c.width > 0 && c.height > 0);
      // `break-all` and `overflow-wrap:anywhere` ask for mid-word breaking on
      // purpose — that is how a long address is kept inside a narrow column. And a
      // word can fit on a line of its own yet not in what is left of the current
      // line, which is ordinary reflow, not a defect.
      const pedidoExpreso =
        estilo.wordBreak === "break-all" || estilo.overflowWrap === "anywhere";
      if (!pedidoExpreso && cajas.length > 1 && anchoDe(palabra, estilo) <= hueco) {
        apilados.push({
          texto: palabra.slice(0, 40), lineas: cajas.length, ancho: Math.round(hueco),
          clase: (padre.className || "").toString().slice(0, 60),
        });
      }
    }

    // ── señal 2: el contenedor es más estrecho que la palabra más larga
    let masLarga = 0, cual = "";
    for (const m of texto.matchAll(/\S+/g)) {
      const w = anchoDe(m[0], estilo);
      if (w > masLarga) { masLarga = w; cual = m[0]; }
    }
    // A heuristic, and deliberately a blunt one: 70%. Below that the container is
    // not merely tight, it has been crushed — the severity cells reached 0% of what
    // "CRÍTICO" needs. Above it, the shortfall is the honest cost of a 33-character
    // address in a narrow column at 320px, where no width would have helped.
    // The 1px tolerance kills equality cases: "seguridad:" reported needing 81px
    // and having 81px, which is sub-pixel rounding, not a layout fault.
    const holgura = 0.7;
    if (hueco <= 1 && masLarga > 0) {
      // Text with no width at all. This is the worst case and the `hueco > 1` guard
      // written for the sub-pixel cases silently excluded it: validated by putting
      // the original bug back, which left the severity labels at exactly 0px and the
      // detector reporting nothing wrong. A check that passes on the broken page is
      // worse than no check.
      estrujados.push({
        texto: cual.slice(0, 40), necesita: Math.round(masLarga), tiene: 0,
        clase: (padre.className || "").toString().slice(0, 60),
      });
    } else if (hueco > 1 && masLarga > hueco + 1 && hueco < masLarga * holgura
        && estilo.whiteSpace !== "nowrap") {
      estrujados.push({
        texto: cual.slice(0, 40), necesita: Math.round(masLarga), tiene: Math.round(hueco),
        clase: (padre.className || "").toString().slice(0, 60),
      });
    }
  }
  regla.remove();

  for (const el of document.querySelectorAll("body *")) {
    const estilo = getComputedStyle(el);
    if (estilo.overflow === "visible") continue;
    if (el.scrollWidth <= el.clientWidth + 1) continue;
    const texto = (el.textContent || "").trim();
    if (!texto) continue;
    cortados.push({
      texto: texto.slice(0, 60), contenido: el.scrollWidth, caja: el.clientWidth,
      clase: (el.className || "").toString().slice(0, 60),
    });
  }

  return {
    apilados, estrujados, cortados,
    desborde: document.documentElement.scrollWidth > window.innerWidth
      ? `${document.documentElement.scrollWidth} > ${window.innerWidth}` : null,
  };
};

/** Adds the score-explanation line the real dashboard shows and the demo does not. */
const INYECTAR = (frase) => {
  const etiqueta = [...document.querySelectorAll("p")].find((e) =>
    // Anchored on BOTH languages: the interface is bilingual now, and an anchor
    // written in one of them makes this script fail for the wrong reason the moment
    // somebody runs it with the language cookie set to the other.
    /^(puntuación de postura|posture score)/.test(e.textContent.trim().toLowerCase())
  );
  if (!etiqueta || !etiqueta.parentElement) return false;
  const caja = document.createElement("div");
  caja.className = "mt-1 space-y-0.5";
  const linea = document.createElement("p");
  // The same classes the component renders, so this measures the shipped markup.
  linea.className = "max-w-[34ch] break-words text-xs text-mist";
  linea.textContent = frase;
  caja.appendChild(linea);
  etiqueta.parentElement.appendChild(caja);
  return true;
};

/** Puts the original bug back and asserts the detector notices.
 *
 * Without this, nobody knows whether the check still works after somebody edits it.
 * It is not hypothetical: two versions of this detector passed cleanly on a page
 * whose severity labels were 0px wide and stacked one letter per line. The first
 * counted `scrollHeight / lineHeight` (padding fooled it); the second guarded on
 * `hueco > 1` to silence sub-pixel noise and thereby skipped every container
 * crushed to exactly zero — the worst case, excluded by the fix for the mildest.
 */
const REINTRODUCIR = (frase) => {
  const et = [...document.querySelectorAll("p")].find((e) =>
    // Anchored on BOTH languages: the interface is bilingual now, and an anchor
    // written in one of them makes this script fail for the wrong reason the moment
    // somebody runs it with the language cookie set to the other.
    /^(puntuación de postura|posture score)/.test(e.textContent.trim().toLowerCase())
  );
  if (!et) return false;
  const der = et.parentElement.parentElement;
  der.classList.add("shrink-0");
  der.classList.remove("min-w-0");
  et.parentElement.classList.remove("min-w-0");
  const q = document.createElement("p");
  q.className = "text-xs text-mist";           // sin max-w ni break-words
  q.textContent = frase;
  et.parentElement.appendChild(q);
  const rejilla = document.querySelector('div[class*="grid-cols-2"]');
  rejilla.style.gridTemplateColumns = "repeat(4, minmax(0, 1fr))";
  [...rejilla.querySelectorAll("p.whitespace-nowrap")].forEach((e) =>
    e.classList.remove("whitespace-nowrap")
  );
  return true;
};

const FRASE_ROTA =
  "la puntuación no se mueve, pero hay 1 cambio(s) en tu organización: son " +
  "demasiado pequeños para mover un número redondeado";

const navegador = await chromium.launch();
let fallos = 0;
let inyecciones = 0;

for (const tema of TEMAS) {
  for (const ancho of ANCHOS) {
    const contexto = await navegador.newContext({
      viewport: { width: ancho, height: 1200 },
      colorScheme: tema,
    });
    const pagina = await contexto.newPage();
    await pagina.goto(`${URL_BASE}/demo`, { waitUntil: "networkidle" });
    await pagina.waitForTimeout(2200);

    if (await pagina.evaluate(INYECTAR, FRASE_LARGA)) inyecciones += 1;
    await pagina.waitForTimeout(300);

    const r = await pagina.evaluate(DETECTAR);
    const mal = r.apilados.length + r.estrujados.length + r.cortados.length + (r.desborde ? 1 : 0);
    fallos += mal;

    const etiqueta = `${tema} ${String(ancho).padStart(4)}px`;
    if (mal === 0) {
      console.log(`  ${etiqueta}  ✓`);
    } else {
      console.log(`  ${etiqueta}  ⚠ ${mal} problema(s)`.replace("problema(s)", mal === 1 ? "problema" : "problemas"));
      for (const a of r.apilados) {
        console.log(`      parte  "${a.texto}" en ${a.lineas} líneas dentro de ${a.ancho}px  <${a.tag}> word-break:${a.wb} overflow-wrap:${a.ow}  [${a.clase}]`);
      }
      for (const e of r.estrujados) {
        console.log(`      estruja "${e.texto}" necesita ${e.necesita}px y tiene ${e.tiene}px  [${e.clase}]`);
      }
      for (const c of r.cortados) {
        console.log(`      corta  ${c.contenido}px en una caja de ${c.caja}px · "${c.texto}"  [${c.clase}]`);
      }
      if (r.desborde) console.log(`      la página desborda: ${r.desborde}`);
    }
    await contexto.close();
  }
}

// ── el detector, probado contra el fallo original
{
  const contexto = await navegador.newContext({
    viewport: { width: 1440, height: 1200 },
    colorScheme: "dark",
  });
  const pagina = await contexto.newPage();
  await pagina.goto(`${URL_BASE}/demo`, { waitUntil: "networkidle" });
  await pagina.waitForTimeout(2200);
  const puesto = await pagina.evaluate(REINTRODUCIR, FRASE_ROTA);
  await pagina.waitForTimeout(400);
  const r = await pagina.evaluate(DETECTAR);
  const visto = r.apilados.length + r.estrujados.length + r.cortados.length;
  await contexto.close();
  if (!puesto) {
    console.error("\n  ✗ no se pudo reintroducir el fallo: el detector queda sin probar");
    await navegador.close();
    process.exit(1);
  }
  if (visto === 0) {
    console.error(
      "\n  ✗ con el fallo original puesto de vuelta, el detector no ve nada. " +
        "No mide lo que dice medir."
    );
    await navegador.close();
    process.exit(1);
  }
  console.log(`\n  autoprueba: con el fallo reintroducido detecta ${visto} problemas ✓`);
}

await navegador.close();

if (inyecciones !== ANCHOS.length * TEMAS.length) {
  console.error(
    `\n  ✗ la frase de regresión solo se pudo inyectar en ${inyecciones} de ` +
      `${ANCHOS.length * TEMAS.length} cargas. El anclaje ("Puntuación de postura") ` +
      `cambió, así que esta comprobación ya no está midiendo el caso que importa.`
  );
  process.exit(1);
}

if (fallos > 0) {
  console.error(`\n  ✗ ${fallos} problema(s) de maquetación`);
  process.exit(1);
}
console.log(`\n  ✓ sin apilados, cortes ni desbordes en ${ANCHOS.length * TEMAS.length} combinaciones`);
