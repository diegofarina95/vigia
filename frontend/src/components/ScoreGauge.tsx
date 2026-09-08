/** The signature dial: a radar-style ring with compass ticks. */
import { getComponentes } from "../content/componentes";
import { useLang } from "../lib/LangContext";
import { DEFAULT_LANG, type Lang } from "../lib/lang";

/** One band table for the colour and the label alike.
 *
 *  These were two functions with two sets of thresholds in the same file, and when
 *  the label gained a fifth band the colour kept the old four — so a 79 would have
 *  shown "Buena, con detalles" in the amber of "Requiere atención". Caught by
 *  `test_bandas_puntuacion.py`, which reads this file and compares the numbers with
 *  `SCORE_BANDS` in `backend/vigia/scoring.py`, the definition both sides mirror.
 *
 *  The screen palette is not the report's: `good` is lighter here because it sits on
 *  ink, and darker there because it sits on white paper. */
const BANDAS = [
  { minimo: 85, clave: "solida", color: "#2f8f63" },
  { minimo: 72, clave: "buena", color: "#63a04a" },
  { minimo: 58, clave: "atencion", color: "#b98a1d" },
  { minimo: 40, clave: "riesgo", color: "#cf6f33" },
  { minimo: 0, clave: "expuesta", color: "#b93a48" },
] as const;

export function scoreColor(score: number | null): string {
  if (score === null) return "#77909f";
  return (BANDAS.find((b) => score >= b.minimo) ?? BANDAS[BANDAS.length - 1]).color;
}

/** `lang` is optional because this is a plain function, not a component, and its
 *  callers are pages that read the language themselves. Left unset it answers in
 *  the default language rather than failing to compile. */
export function scoreLabel(score: number | null, lang: Lang = DEFAULT_LANG): string {
  const t = getComponentes(lang).medidor;
  // Mirrors `SCORE_BANDS` in `backend/vigia/scoring.py`, which is the definition.
  // `test_bandas_puntuacion.py` reads this file and fails if the numbers drift:
  // the panel and the PDF must not disagree about the same score.
  if (score === null) return t.sinDeterminar;
  const banda = BANDAS.find((b) => score >= b.minimo) ?? BANDAS[BANDAS.length - 1];
  return t[banda.clave];
}

export default function ScoreGauge({
  score,
  onDark = false,
}: {
  score: number | null;
  onDark?: boolean;
}) {
  const { lang } = useLang();
  const t = getComponentes(lang).medidor;
  const radius = 62;
  const circumference = 2 * Math.PI * radius;
  const fraction = score === null ? 0 : score / 100;
  const color = scoreColor(score);

  const ticks = Array.from({ length: 36 }, (_, index) => {
    const angle = (index * 10 * Math.PI) / 180;
    const major = index % 9 === 0;
    const outer = 76;
    const inner = major ? 68 : 72;
    return (
      <line
        key={index}
        x1={80 + Math.sin(angle) * inner}
        y1={80 - Math.cos(angle) * inner}
        x2={80 + Math.sin(angle) * outer}
        y2={80 - Math.cos(angle) * outer}
        stroke={major ? (onDark ? "#5f7d92" : "#5c7183") : onDark ? "#26445c" : "#dde5e3"}
        strokeWidth={major ? 1.5 : 1}
      />
    );
  });

  return (
    <svg width="160" height="160" viewBox="0 0 160 160" role="img"
      aria-label={score === null ? t.ariaSinDeterminar : t.aria(score)}>
      {ticks}
      <circle cx="80" cy="80" r={radius} fill="none" stroke={onDark ? "#1b3b52" : "#e8eeec"} strokeWidth="9" />
      <circle
        cx="80"
        cy="80"
        r={radius}
        fill="none"
        stroke={color}
        strokeWidth="9"
        strokeLinecap="round"
        strokeDasharray={`${circumference * fraction} ${circumference}`}
        transform="rotate(-90 80 80)"
        style={{ transition: "stroke-dasharray 900ms ease" }}
      />
      <text
        x="80"
        y="84"
        textAnchor="middle"
        fontFamily="IBM Plex Mono, monospace"
        fontSize="38"
        fontWeight="600"
        fill={onDark ? "#ffffff" : "#0d1f2d"}
      >
        {score === null ? "—" : score}
      </text>
      <text
        x="80"
        y="104"
        textAnchor="middle"
        fontFamily="IBM Plex Mono, monospace"
        fontSize="10"
        fill={onDark ? "#9db4c4" : "#5c7183"}
      >
        / 100
      </text>
    </svg>
  );
}
