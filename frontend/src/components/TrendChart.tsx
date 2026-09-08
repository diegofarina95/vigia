import { getComponentes } from "../content/componentes";
import { useLang } from "../lib/LangContext";
import type { HistoryEntry } from "../types";
import { scoreColor } from "./ScoreGauge";

/** One point per DAY (the last scan of each day), because two scans ten
 * minutes apart plotted as a time series reads as broken, not as history. */
export function dailyPoints(history: HistoryEntry[]): HistoryEntry[] {
  const byDay = new Map<string, HistoryEntry>();
  for (const entry of history) {
    if (entry.score === null) continue;
    const day = entry.created_at.slice(0, 10);
    // history arrives oldest-first, so the last write per day wins — but the
    // engine break must survive the collapse. Several scans can land on one
    // day with the check set changing between them, and keeping only the last
    // would silently reconnect a line across two different yardsticks.
    const kept = byDay.get(day);
    byDay.set(day, {
      ...entry,
      engine_changed: entry.engine_changed || kept?.engine_changed || false,
    });
  }
  return [...byDay.values()];
}

/** Dependency-free score-over-time line chart. */
export default function TrendChart({ history }: { history: HistoryEntry[] }) {
  const { lang } = useLang();
  const t = getComponentes(lang).tendencia;
  const points = dailyPoints(history);
  if (points.length < 2) return null;

  const width = 560;
  const height = 140;
  const padX = 30;
  const padY = 16;
  const stepX = points.length > 1 ? (width - padX * 2) / (points.length - 1) : 0;

  const coords = points.map((entry, index) => ({
    x: padX + index * stepX,
    y: padY + (1 - (entry.score as number) / 100) * (height - padY * 2),
    entry,
  }));

  // The line breaks wherever the engine changed. Drawing through it would
  // claim a trend across two different sets of checks — the score is a
  // fraction of the weight the engine can award, so adding checks moves it
  // without the tenant touching anything.
  const path = coords
    .map((c, i) => `${i === 0 || c.entry.engine_changed ? "M" : "L"}${c.x},${c.y}`)
    .join(" ");
  const breaks = coords.filter((c, i) => i > 0 && c.entry.engine_changed);

  return (
    <svg
      viewBox={`0 0 ${width} ${height + 20}`}
      className="w-full"
      role="img"
      aria-label={t.aria}
    >
      {[100, 50, 0].map((line) => {
        const y = padY + (1 - line / 100) * (height - padY * 2);
        return (
          <g key={line}>
            <line x1={padX} y1={y} x2={width - padX} y2={y} stroke="#dde5e3" strokeDasharray="3 4" />
            <text x={padX - 8} y={y + 3} textAnchor="end" fontSize="9" fontFamily="IBM Plex Mono, monospace" fill="#5c7183">
              {line}
            </text>
          </g>
        );
      })}
      <path d={path} fill="none" stroke="#14324a" strokeWidth="2" />
      {breaks.map(({ x, entry }) => (
        <g key={`corte-${entry.id}`}>
          <line
            x1={x - stepX / 2}
            y1={padY - 6}
            x2={x - stepX / 2}
            y2={height - padY + 6}
            stroke="#f2b63c"
            strokeWidth="1.5"
            strokeDasharray="2 3"
          />
          <title>{t.corte}</title>
        </g>
      ))}
      {coords.map(({ x, y, entry }) => (
        <g key={entry.id}>
          <circle cx={x} cy={y} r="4" fill={scoreColor(entry.score)} stroke="#fff" strokeWidth="1.5">
            <title>
              {`${new Date(entry.created_at).toLocaleDateString(t.localeFecha)} — ${entry.score}` +
                (entry.engine_changed ? t.puntoCambio : "")}
            </title>
          </circle>
          <text x={x} y={height + 12} textAnchor="middle" fontSize="9" fontFamily="IBM Plex Mono, monospace" fill="#5c7183">
            {new Date(entry.created_at).toLocaleDateString(t.localeFecha, {
              day: "numeric",
              month: "short",
            })}
          </text>
        </g>
      ))}
    </svg>
  );
}
