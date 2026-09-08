/**
 * Layout regression test for the dashboard header.
 *
 * The header printed "CRÍTICO" as a vertical column of letters, one per line, and
 * the summary sentence as a column one word wide, while half the panel sat empty.
 * Four reported symptoms, one cause: the score column carried `shrink-0` with an
 * unbounded sentence inside it, so flexbox took every pixel of shrinkage out of its
 * sibling, and Tailwind's `grid-cols-4` compiles to `minmax(0, 1fr)` — that zero
 * let each counter cell be crushed to 0px, below the width of its own word.
 *
 * Nothing caught it. The unit tests assert text, not geometry, and the bug only
 * appears when the score does NOT move and the organisation changed anyway, which
 * is a state the demo data never reaches. So this test injects exactly that
 * sentence into the demo report and then measures.
 *
 * How it detects stacking: for each text node it counts real line boxes via
 * `Range.getClientRects()` and compares against the word count. More line boxes
 * than words means the text is breaking inside words. `scrollHeight / lineHeight`
 * was tried first and is useless — it includes padding, and on SVG text it means
 * nothing, which produced 28 false positives and hid the actual defect.
 *
 * Run: node frontend/tests/layout-cabecera.mjs [url]
 * Requires the app to be reachable. Exits non-zero on any finding.
 */
import { chromium } from "playwright-core";

const BASE = process.argv[2] || "https://diegofarina.com/vigia";

/** The exact sentence that triggered it, before it was reworded. Kept verbatim on
 *  purpose: the regression case is a long line in that column, whatever it says. */
const FRASE_LARGA =
  "la puntuación no se mueve, pero hay 1 cambio(s) en tu organización: " +
  "son demasiado pequeños para mover un número redondeado";

const ANCHOS = [1440, 1280, 1024, 768, 390, 320];

const medir = () => {
  const fallos = [];
  const paseo = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
  for (let n = paseo.nextNode(); n; n = paseo.nextNode()) {
    const texto = (n.nodeValue || "").trim();
    if (texto.length < 2) continue;
    const padre = n.parentElement;
    if (!padre || padre.closest("svg")) continue;
    const r = document.createRange();
    r.selectNodeContents(n);
    const cajas = [...r.getClientRects()].filter((c) => c.width > 0 && c.height > 0);
    const palabras = texto.split(/\s+/).length;
    // A single token with no spaces — an e-mail address, a URL — has no legal break
    // point, so at 320px it MUST break mid-token and that is correct, not a defect.
    // Only multi-word text that uses more line boxes than it has words is stacking.
    if (palabras < 2) continue;
    if (cajas.length > palabras && cajas.length > 1) {
      fallos.push(
        `apilado: "${texto.slice(0, 44)}" en ${cajas.length} líneas para ${palabras} palabra(s), ` +
          `contenedor de ${Math.round(padre.getBoundingClientRect().width)}px`
      );
    }
  }
  for (const e of document.querySelectorAll("body *")) {
    if (getComputedStyle(e).overflow === "visible") continue;
    if (e.scrollWidth <= e.clientWidth + 1) continue;
    const t = (e.textContent || "").trim();
    if (t) fallos.push(`cortado: "${t.slice(0, 44)}" ${e.scrollWidth}px en caja de ${e.clientWidth}px`);
  }
  if (document.documentElement.scrollWidth > window.innerWidth) {
    fallos.push(`la página desborda: ${document.documentElement.scrollWidth} > ${window.innerWidth}`);
  }
  return fallos;
};

const navegador = await chromium.launch();
let total = 0;

for (const tema of ["dark", "light"]) {
  for (const ancho of ANCHOS) {
    const ctx = await navegador.newContext({
      viewport: { width: ancho, height: 1200 },
      colorScheme: tema,
    });
    const pagina = await ctx.newPage();
    await pagina.goto(`${BASE}/demo`, { waitUntil: "networkidle" });
    await pagina.waitForTimeout(2200);

    // The state the bug needs: a long explanation line in the score column. Located
    // by its label rather than by class, so the test survives the next refactor.
    const inyectado = await pagina.evaluate((frase) => {
      const etiqueta = [...document.querySelectorAll("p")].find((e) =>
        e.textContent.trim().toLowerCase().startsWith("puntuación de postura")
      );
      if (!etiqueta || !etiqueta.parentElement) return false;
      const caja = document.createElement("div");
      caja.className = "mt-1 space-y-0.5";
      const linea = document.createElement("p");
      linea.className = "max-w-[34ch] break-words text-xs text-mist";
      linea.textContent = frase;
      caja.appendChild(linea);
      etiqueta.parentElement.appendChild(caja);
      return true;
    }, FRASE_LARGA);

    if (!inyectado) {
      console.error(`  ✗ ${tema} ${ancho}px: no encuentro la columna de puntuación`);
      total += 1;
      await ctx.close();
      continue;
    }
    await pagina.waitForTimeout(300);

    const fallos = await pagina.evaluate(medir);
    if (fallos.length) {
      console.error(`  ✗ ${tema} ${ancho}px — ${fallos.length}`);
      for (const f of fallos) console.error(`      ${f}`);
      total += fallos.length;
    } else {
      console.log(`  ✓ ${tema} ${ancho}px`);
    }
    await ctx.close();
  }
}

await navegador.close();
if (total) {
  console.error(`\n  ${total} fallo(s) de maquetación`);
  process.exit(1);
}
console.log("\n  maquetación de la cabecera: sin apilados, sin cortes, sin desbordes");
