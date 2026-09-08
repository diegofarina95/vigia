export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Status = "pass" | "fail" | "warn" | "undetermined";

/** Two axes, not one. `new`/`worse`/`improved`/`resolved` are statements about
 *  the tenant; `coverage_gained`/`coverage_lost` are statements about what Vigía
 *  can reach. `undetermined → pass` used to arrive here as `resolved`, so the
 *  product congratulated the customer for something it had merely started being
 *  able to read. */
export type Change =
  | "new"
  | "worse"
  | "improved"
  | "resolved"
  | "coverage_gained"
  | "coverage_lost"
  | "same"
  | "baseline";

export interface ChangeDetail {
  from_status?: Status;
  to_status?: Status;
  from_severity?: Severity;
  to_severity?: Severity;
  from_count?: number;
  to_count?: number;
  regression?: boolean;
  open?: boolean;
}

/** Why the score moved, split by cause. */
export interface ScoreChange {
  score: number | null;
  previous_score: number | null;
  total: number | null;
  /** The part the tenant caused, recomputed over the items scored in both
   *  scans. `null` when one of the two was stored without a breakdown. */
  exposure: number | null;
  /** The part our own coverage caused: total − exposure. */
  coverage: number | null;
  gained: string[];
  lost: string[];
  common: number;
  reason: string;
}

export interface Finding {
  /** "organization" — a tenant setting, nobody's personal failing.
   *  "accounts"     — something true of the people it names.
   *  Optional: scans stored before the field existed do not carry it. */
  scope_type?: "organization" | "accounts";
  id: string;
  title: string;
  severity: Severity;
  status: Status;
  change?: Change;
  change_detail?: ChangeDetail;
  description: string;
  affected_items: string[];
  remediation: string;
  admin_console_url: string;
  cis_control: string;
  scope_label?: string;
  /** The measured value of a setting, e.g. "Periodo de gracia: 14 día(s)".
   *  A separate field from the description because the translation catalogue
   *  replaces descriptions wholesale and used to delete it. */
  observed_value?: string;
  /** Only on account-scoped findings, and only on scans stored since the
   *  scope field existed — hence the fallback in the dashboard. */
  accounts?: string[];
  manual: boolean;
  details: Record<string, unknown>;
}

export interface ManualCheck {
  id: string;
  title: string;
  severity: Severity;
  area: string;
  why_manual: string;
  instructions: string[];
  admin_console_url: string;
  cis_control: string;
}

export interface Scan {
  id: number;
  created_at: string;
  score: number | null;
  counts: Record<Severity, number>;
  findings: Finding[];
  manual_checks: ManualCheck[];
}

export interface DeltaEntry {
  id: string;
  title: string;
  severity: Severity;
  /** The drift numbers, when the entry has them: the backend sends data rather
   *  than a rendered sentence, because a sentence written into a catalogue-managed
   *  field gets replaced on the way out. */
  from_count?: number;
  to_count?: number;
  from_severity?: Severity;
  to_severity?: Severity;
  from_status?: Status;
  to_status?: Status;
  regression?: boolean;
  /** `coverage_gained` only: the newly readable check turned out to be an open
   *  issue. Not new in the tenant — it was invisible, not absent. */
  open?: boolean;
}

export interface DeltaSummary {
  has_baseline: boolean;
  /** The set of checks changed between the two scans, so no comparison is
   *  possible. Showing "no change" here would be a false statement about the
   *  tenant: what changed was the yardstick. */
  engine_changed?: boolean;
  engine_version?: string;
  previous_engine?: string;
  note?: string;
  new: DeltaEntry[];
  worse: DeltaEntry[];
  improved: DeltaEntry[];
  resolved: DeltaEntry[];
  coverage_gained?: DeltaEntry[];
  coverage_lost?: DeltaEntry[];
  score_change?: ScoreChange | null;
  /** The decomposition already rendered, by the backend, in the same words the
   *  PDF and the e-mail use. Rebuilding these sentences here is what let four
   *  channels describe one comparison four ways. */
  score_lines?: string[];
}

export interface RemediationAction {
  id: string;
  title: string;
  console_path: string;
  console_url: string;
  minutes: number;
  user_impact: string | null;
  findings_closed: number;
  criticals_closed: number;
  highs_closed: number;
  accounts_affected: number;
  score_gain: number;
  finding_ids: string[];
  finding_titles: string[];
  leverage: number;
}

export interface BreakdownAccountRow {
  account: string;
  severity: Severity;
  status: Status;
  finding_id: string;
  weight: number;
  credit: number;
  earned: number;
  also_in: string[];
}

export interface BreakdownFindingRow {
  id: string;
  title: string;
  severity: Severity;
  status: Status;
  weight: number;
  earned: number;
}

export interface ScoreBreakdown {
  score: number | null;
  /** How much the per-account block was scaled down so it would not outweigh
   *  the organization block. 1 means untouched, which is the common case. */
  people_scale?: number;
  people_weight?: number;
  org_weight?: number;
  total_weight: number;
  earned_weight: number;
  lost_weight: number;
  accounts: BreakdownAccountRow[];
  findings: BreakdownFindingRow[];
  excluded: { id: string; severity: Severity; status: Status; reason: string }[];
  weights: Record<Severity, number>;
  credits: Record<string, number>;
}

export interface PersonAtRisk {
  account: string;
  worst: Severity;
  weight: number;
  issues: { id: string; title: string; severity: Severity }[];
}

export interface LatestResponse {
  demo?: boolean;
  org?: { domain: string; admin_email: string };
  scan: Scan | null;
  previous_score: number | null;
  delta: DeltaSummary | null;
  actions?: RemediationAction[];
  breakdown?: ScoreBreakdown | null;
  people_at_risk?: PersonAtRisk[];
}

export interface Schedule {
  frequency: "off" | "daily" | "weekly";
  alert_email: string;
  suggested_email?: string;
  alert_only_on_change: boolean;
  last_run: string | null;
  smtp_configured: boolean;
  frequencies: string[];
}

export interface HistoryEntry {
  /** True when the set of checks changed at this point, so the line must not
   *  be drawn through it: the two sides measure different things. */
  engine_changed?: boolean;
  engine_version?: string;
  id: number;
  created_at: string;
  score: number | null;
  counts: Record<Severity, number>;
}

export interface HistoryResponse {
  history: HistoryEntry[];
  truncated: boolean;
}

export interface Me {
  connected: boolean;
  mock_mode: boolean;
  contact_email?: string;
  org?: { domain: string; admin_email: string };
}

export interface DomainInfo {
  domain: string;
  source: "google" | "custom";
  added_at: string;
}

export interface DomainsResponse {
  domains: DomainInfo[];
}

/** Per-domain DNS detail, as stored in the email-auth findings' details. */
export interface DomainCheckDetail {
  status: Status;
  summary: string;
  record?: string | null;
  found?: boolean | null;
  all_qualifier?: string | null;
  dns_lookups?: number | null;
  selector?: string | null;
  key_bits?: number | null;
  checked_selectors?: string[];
  policy?: string | null;
  adkim?: string;
  aspf?: string;
  rua?: string[];
  rua_destination?: string | null;
  issues?: string[];
}

export interface ScanSettings {
  super_admin_threshold: number;
  dormant_days: number;
  widely_granted_threshold: number;
  dkim_selectors: string[];
}

export interface SettingsResponse {
  settings: ScanSettings;
  defaults: ScanSettings;
}

export interface MechanismResult {
  status: Status;
  summary: string;
  record?: string | null;
  found?: boolean | null;
  issues?: string[];
  policy?: string | null;
  subdomain_policy?: string | null;
  selector?: string | null;
  checked_selectors?: string[];
  rua?: string[];
  pct?: number;
  all_qualifier?: string | null;
  lookup_terms?: number;
  error?: string | null;
}

export interface TransportResult {
  status: Status;
  summary: string;
  value: boolean | null;
  record: string | null;
}

export interface EmailAuthReport {
  domain: string;
  spf: MechanismResult;
  dkim: MechanismResult;
  dmarc: MechanismResult;
  mta_sts: TransportResult;
  tls_rpt: TransportResult;
  dnssec: TransportResult;
  mx: { records: string[]; google_workspace: boolean | null; error: string | null };
}
