/** Runtime mount-prefix detection: the same build must work at "/"
 * (direct Tailscale access) and under a public mount path like "/vigia"
 * (diegofarina.com → Worker → Funnel). If the first path segment is not
 * one of the app's own routes, it is the mount prefix. */
const APP_ROUTES = new Set(["", "dashboard", "dmarc-checker", "privacy", "demo"]);

const firstSegment = window.location.pathname.split("/")[1] ?? "";

export const APP_PREFIX = APP_ROUTES.has(firstSegment) ? "" : `/${firstSegment}`;
