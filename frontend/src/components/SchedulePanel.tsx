/* NOT MOUNTED. Recurring scans and e-mail alerts are the monthly-monitoring
 * product, not yet being sold, so the screen is gone while `jobs.py`, the
 * `schedule_*` columns and `db.set_schedule` stay exactly as they were. The
 * product default is now `off` and `PUT /api/schedule` and `POST /api/notify/test`
 * are gone: a schedule nobody can see is a schedule nobody can stop. Remounting
 * means restoring those two routes. */
import { useEffect, useState } from "react";
import { ApiError, api } from "../api";
import { getComponentes } from "../content/componentes";
import { useLang } from "../lib/LangContext";
import type { Schedule } from "../types";

export default function SchedulePanel() {
  const { lang } = useLang();
  const t = getComponentes(lang).programacion;
  const [schedule, setSchedule] = useState<Schedule | null>(null);
  const [frequency, setFrequency] = useState("off");
  const [email, setEmail] = useState("");
  const [onlyOnChange, setOnlyOnChange] = useState(true);
  const [message, setMessage] = useState<{ kind: "ok" | "error"; text: string } | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    api
      .schedule()
      .then((data) => {
        setSchedule(data);
        setFrequency(data.frequency);
        setEmail(data.alert_email);
        setOnlyOnChange(data.alert_only_on_change);
      })
      .catch(() => {});
  }, []);

  async function save(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setMessage(null);
    try {
      const saved = await api.saveSchedule({
        frequency,
        alert_email: email,
        alert_only_on_change: onlyOnChange,
      });
      setSchedule(saved);
      setMessage({
        kind: "ok",
        text:
          saved.frequency === "off"
            ? t.guardadoDesactivado
            : t.guardadoActivo(t.frecuencias[saved.frequency] ?? saved.frequency),
      });
    } catch (err) {
      setMessage({
        kind: "error",
        text: err instanceof ApiError ? err.message : t.errorGuardar,
      });
    } finally {
      setBusy(false);
    }
  }

  async function sendTest() {
    setBusy(true);
    setMessage(null);
    try {
      const result = await api.sendTestAlert(email);
      setMessage({ kind: "ok", text: t.pruebaEnviada(result.sent_to) });
    } catch (err) {
      setMessage({
        kind: "error",
        text: err instanceof ApiError ? err.message : t.errorPrueba,
      });
    } finally {
      setBusy(false);
    }
  }

  if (!schedule) return null;

  return (
    <section className="rounded-lg border border-line bg-card p-6">
      <div className="mb-1 flex flex-wrap items-center justify-between gap-2">
        <h2 className="font-display text-lg font-bold text-strong">{t.titulo}</h2>
        {schedule.last_run && (
          <span className="font-mono text-[11px] text-dim">
            {t.ultimo} {new Date(schedule.last_run).toLocaleString()}
          </span>
        )}
      </div>
      <p className="mb-4 text-sm text-dim">{t.intro}</p>

      <form onSubmit={save} className="space-y-4">
        <div className="grid gap-4 sm:grid-cols-2">
          <div>
            <label htmlFor="frequency" className="mb-1 block text-sm font-medium text-strong">
              {t.frecuenciaEtiqueta}
            </label>
            <select
              id="frequency"
              value={frequency}
              onChange={(event) => setFrequency(event.target.value)}
              className="w-full rounded-md border border-line bg-paper px-3 py-2 text-sm focus:border-ink-3 focus:outline-none"
            >
              {schedule.frequencies.map((option) => (
                <option key={option} value={option}>
                  {t.frecuencias[option] ?? option}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label htmlFor="alert-email" className="mb-1 block text-sm font-medium text-strong">
              {t.avisosEtiqueta}
            </label>
            <input
              id="alert-email"
              type="email"
              value={email}
              onChange={(event) => setEmail(event.target.value)}
              // Never a fake placeholder: the default is the admin who connected.
              placeholder={schedule.suggested_email || "you@yourdomain.com"}
              className="w-full rounded-md border border-line bg-paper px-3 py-2 font-mono text-sm focus:border-ink-3 focus:outline-none"
            />
          </div>
        </div>

        <label className="flex cursor-pointer items-start gap-2 text-sm">
          <input
            type="checkbox"
            checked={onlyOnChange}
            onChange={(event) => setOnlyOnChange(event.target.checked)}
            className="mt-0.5 accent-ink"
          />
          <span>
            {t.soloCambios}
            <span className="block text-xs text-dim">{t.soloCambiosAyuda}</span>
          </span>
        </label>

        {!schedule.smtp_configured && (
          <p className="rounded-md border border-sev-medium/40 bg-sev-medium/10 px-3 py-2 text-xs text-sev-medium">
            {t.sinSmtpAntes}
            <code className="font-mono">VIGIA_SMTP_HOST</code>
            {t.sinSmtpY}
            <code className="font-mono">VIGIA_SMTP_FROM</code>
            {t.sinSmtpDespues}
          </p>
        )}

        <div className="flex flex-wrap items-center gap-3">
          <button
            type="submit"
            disabled={busy}
            className="rounded-md bg-ink px-4 py-2 text-sm font-semibold text-white transition hover:bg-ink-2 disabled:opacity-50"
          >
            {busy ? t.guardando : t.guardar}
          </button>
          <button
            type="button"
            onClick={sendTest}
            disabled={busy || !email || !schedule.smtp_configured}
            className="rounded-md border border-line px-4 py-2 text-sm text-dim transition hover:border-ink-3 hover:text-strong disabled:opacity-40"
          >
            {t.enviarPrueba}
          </button>
          {message && (
            <span className={`text-sm ${message.kind === "ok" ? "text-ok" : "text-bad"}`}>
              {message.text}
            </span>
          )}
        </div>
      </form>
    </section>
  );
}
