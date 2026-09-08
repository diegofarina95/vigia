/* NOT MOUNTED, and this one should NOT come back as it was. These four
 * thresholds let the tenant being measured move its own yardstick: set
 * `dormant_days` to 3650 and the dormant-accounts finding disappears. The
 * authority of the report comes from measuring against CIS, so the values are
 * fixed in `services.SCORING_THRESHOLDS` and `PUT /api/settings` is gone. Kept
 * only as the shape of a future read-only 'these are the thresholds we used'
 * disclosure — `GET /api/settings` still serves them. */
import { useEffect, useState } from "react";
import { ApiError, api } from "../api";
import { getComponentes } from "../content/componentes";
import { useLang } from "../lib/LangContext";
import type { ScanSettings } from "../types";

interface FormState {
  super_admin_threshold: string;
  dormant_days: string;
  widely_granted_threshold: string;
  dkim_selectors: string;
}

function toForm(settings: ScanSettings): FormState {
  return {
    super_admin_threshold: String(settings.super_admin_threshold),
    dormant_days: String(settings.dormant_days),
    widely_granted_threshold: String(settings.widely_granted_threshold),
    dkim_selectors: settings.dkim_selectors.join(", "),
  };
}

/** Which fields the form shows, in order. The label and the help text live in
 *  `content/componentes.ts`, keyed by the same name. */
const FIELDS: {
  key: keyof FormState;
  type: "number" | "text";
}[] = [
  { key: "super_admin_threshold", type: "number" },
  { key: "dormant_days", type: "number" },
  { key: "widely_granted_threshold", type: "number" },
  { key: "dkim_selectors", type: "text" },
];

export default function SettingsPanel() {
  const { lang } = useLang();
  const t = getComponentes(lang).opciones;
  const [open, setOpen] = useState(false);
  const [form, setForm] = useState<FormState | null>(null);
  const [defaults, setDefaults] = useState<ScanSettings | null>(null);
  const [message, setMessage] = useState<{ kind: "ok" | "error"; text: string } | null>(null);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    api
      .scanSettings()
      .then((response) => {
        setForm(toForm(response.settings));
        setDefaults(response.defaults);
      })
      .catch(() => {});
  }, []);

  async function save(event: React.FormEvent) {
    event.preventDefault();
    if (!form) return;
    setSaving(true);
    setMessage(null);
    try {
      const response = await api.saveScanSettings({
        super_admin_threshold: Number(form.super_admin_threshold),
        dormant_days: Number(form.dormant_days),
        widely_granted_threshold: Number(form.widely_granted_threshold),
        dkim_selectors: form.dkim_selectors,
      });
      setForm(toForm(response.settings));
      setMessage({ kind: "ok", text: t.guardado });
    } catch (err) {
      setMessage({
        kind: "error",
        text: err instanceof ApiError ? err.message : t.errorGuardar,
      });
    } finally {
      setSaving(false);
    }
  }

  function resetToDefaults() {
    if (defaults) {
      setForm(toForm(defaults));
      setMessage(null);
    }
  }

  return (
    <section className="rounded-lg border border-line bg-card">
      <button
        onClick={() => setOpen(!open)}
        aria-expanded={open}
        className="flex w-full items-center justify-between px-6 py-4 text-left"
      >
        <span>
          <span className="font-display text-lg font-bold text-strong">{t.titulo}</span>
          <span className="ml-3 font-mono text-[11px] text-dim">{t.subtitulo}</span>
        </span>
        <span className={`text-dim transition-transform ${open ? "rotate-180" : ""}`} aria-hidden>
          ▾
        </span>
      </button>

      {open && form && (
        <form onSubmit={save} className="space-y-5 border-t border-line px-6 py-5">
          <div className="grid gap-5 sm:grid-cols-2">
            {FIELDS.map(({ key, type }) => (
              <div key={key} className={type === "text" ? "sm:col-span-2" : ""}>
                <label htmlFor={key} className="mb-1 block text-sm font-medium text-strong">
                  {t.campos[key].etiqueta}
                </label>
                <input
                  id={key}
                  type={type}
                  value={form[key]}
                  onChange={(event) => setForm({ ...form, [key]: event.target.value })}
                  className="w-full rounded-md border border-line bg-paper px-3 py-2 font-mono text-sm focus:border-ink-3 focus:outline-none"
                />
                <p className="mt-1 text-xs text-dim">{t.campos[key].ayuda}</p>
              </div>
            ))}
          </div>
          <div className="flex flex-wrap items-center gap-3">
            <button
              type="submit"
              disabled={saving}
              className="rounded-md bg-ink px-4 py-2 text-sm font-semibold text-white transition hover:bg-ink-2 disabled:opacity-50"
            >
              {saving ? t.guardando : t.guardar}
            </button>
            <button
              type="button"
              onClick={resetToDefaults}
              className="rounded-md border border-line px-4 py-2 text-sm text-dim transition hover:border-ink-3 hover:text-strong"
            >
              {t.restaurar}
            </button>
            {message && (
              <span className={`text-sm ${message.kind === "ok" ? "text-ok" : "text-bad"}`}>
                {message.text}
              </span>
            )}
          </div>
        </form>
      )}
    </section>
  );
}
