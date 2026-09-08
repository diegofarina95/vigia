"""The findings catalogue: what each hook says, in both languages.

Ranked by **commercial impact, not technical severity**. Those two disagree, and
the disagreement is the point of this file. DNSSEC being off is technically more
alarming than a `p=none` DMARC record, but "anyone can send email pretending to be
you" is a sentence a finance director acts on and "your DNS responses are not
signed" is one they forward to somebody who never replies.

Rank 1 is the strongest hook, rank 6 the weakest. Exactly one finding becomes the
subject line, so the ranking is the whole product decision.

Two fields exist that the brief did not ask for, and both are here to stop this
module sending something untrue:

* `requires_assertable_absence` — the finding may only fire when the scanner can
  *assert* the absence, not merely fail to find it. DKIM selectors cannot be
  enumerated, so "not found" and "not signed" are different statements.
* `meaningful_without_mx` — whether the finding still means anything for a domain
  that receives no mail. MTA-STS protects inbound mail; on a domain with no MX
  there is no inbound mail to protect, so the finding is not weak evidence, it is
  no evidence.

The wording is deliberately plain. A subject line that needs decoding is a subject
line that does not get opened.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CatalogEntry:
    """One hook, in one language."""

    code: str
    lang: str
    severity_rank: int
    technical_description: str
    plain_language_description: str
    subject_line_template: str
    opening_line_template: str


@dataclass(frozen=True)
class FindingRule:
    """The language-independent half: rank and the rules for firing."""

    code: str
    severity_rank: int
    requires_assertable_absence: bool = False
    meaningful_without_mx: bool = True


#: The ranking, and the only place it is written down.
RULES: tuple[FindingRule, ...] = (
    FindingRule("dmarc-missing", 1),
    FindingRule("spf-lookup-limit", 2),
    FindingRule("dkim-missing", 3, requires_assertable_absence=True),
    FindingRule("spf-soft-all", 4),
    FindingRule("dmarc-none-no-rua", 5),
    # MTA-STS governs mail arriving AT the domain. With no MX there is nothing
    # arriving, so this is not a weaker version of the same argument — there is no
    # argument. It is dropped rather than deprioritised.
    FindingRule("mta-sts-missing", 6, meaningful_without_mx=False),
)

RULES_BY_CODE: dict[str, FindingRule] = {rule.code: rule for rule in RULES}


#: `{company_name}` and `{domain}` are the only placeholders these carry. Every one
#: is filled by Phase 2's renderer, which refuses to emit a body with an unfilled
#: placeholder in it — "{company_name}" arriving in a stranger's inbox is worse
#: than not writing to them.
CATALOG: tuple[CatalogEntry, ...] = (
    # ---------------------------------------------------------------- rank 1
    CatalogEntry(
        code="dmarc-missing",
        lang="es",
        severity_rank=1,
        technical_description=(
            "No hay ningún registro DMARC publicado en _dmarc.{domain}, así que los "
            "servidores que reciben correo no tienen ninguna instrucción sobre qué hacer "
            "con los mensajes que dicen venir de este dominio y no lo hacen."
        ),
        plain_language_description=(
            "Cualquiera puede mandar correo haciéndose pasar por {domain}. Hoy no hay nada "
            "configurado que le diga a Gmail o a Outlook que rechace esos mensajes, así que "
            "llegan a la bandeja de entrada de vuestros clientes con vuestro nombre encima."
        ),
        subject_line_template="Cualquiera puede enviar correo en nombre de {domain}",
        opening_line_template=(
            "He comprobado la configuración pública de correo de {domain} y falta una pieza "
            "que hoy permite que un tercero escriba a vuestros clientes usando vuestra "
            "dirección."
        ),
    ),
    CatalogEntry(
        code="dmarc-missing",
        lang="en",
        severity_rank=1,
        technical_description=(
            "No DMARC record is published at _dmarc.{domain}, so receiving mail servers have "
            "no instruction about what to do with messages that claim to come from this "
            "domain and do not."
        ),
        plain_language_description=(
            "Anyone can send email pretending to be {domain}. There is nothing in place today "
            "telling Gmail or Outlook to reject those messages, so they reach your customers' "
            "inboxes with your name on them."
        ),
        subject_line_template="Anyone can send email as {domain}",
        opening_line_template=(
            "I checked the public mail configuration of {domain} and one piece is missing that "
            "currently lets a stranger write to your customers using your address."
        ),
    ),
    # ---------------------------------------------------------------- rank 2
    CatalogEntry(
        code="spf-lookup-limit",
        lang="es",
        severity_rank=2,
        technical_description=(
            "El registro SPF de {domain} supera el límite de 10 consultas DNS del RFC 7208. "
            "Los receptores devuelven permerror y, según su política, tratan el resultado como "
            "si el SPF no existiera."
        ),
        plain_language_description=(
            "El SPF de {domain} está roto de una forma que no da ningún aviso: supera un límite "
            "técnico y muchos servidores dejan de comprobarlo. El correto legítimo que enviáis "
            "empieza a caer en spam sin que nadie os diga por qué."
        ),
        subject_line_template="El SPF de {domain} falla en silencio",
        opening_line_template=(
            "El registro SPF de {domain} supera un límite técnico que hace que muchos "
            "servidores dejen de validarlo, y eso se nota en que vuestro correo legítimo acaba "
            "en spam sin explicación."
        ),
    ),
    CatalogEntry(
        code="spf-lookup-limit",
        lang="en",
        severity_rank=2,
        technical_description=(
            "The SPF record for {domain} exceeds the RFC 7208 limit of 10 DNS lookups. "
            "Receivers return permerror and, depending on their policy, treat the result as if "
            "no SPF record existed."
        ),
        plain_language_description=(
            "The SPF record for {domain} is broken in a way that gives no warning: it goes over "
            "a technical limit and many servers stop checking it. Legitimate mail you send "
            "starts landing in spam with nobody telling you why."
        ),
        subject_line_template="{domain}'s SPF is failing silently",
        opening_line_template=(
            "The SPF record for {domain} goes over a technical limit that makes many servers "
            "stop validating it, which shows up as your legitimate mail landing in spam for no "
            "apparent reason."
        ),
    ),
    # ---------------------------------------------------------------- rank 3
    CatalogEntry(
        code="dkim-missing",
        lang="es",
        severity_rank=3,
        technical_description=(
            "No hay clave DKIM publicada en el selector declarado para {domain}, así que los "
            "mensajes salen sin firma criptográfica y no se puede demostrar que no han sido "
            "modificados en tránsito."
        ),
        plain_language_description=(
            "El correo que sale de {domain} no va firmado. Sin esa firma, el servidor que lo "
            "recibe no tiene forma de comprobar que el mensaje es vuestro de verdad y lo trata "
            "con más desconfianza."
        ),
        subject_line_template="El correo de {domain} sale sin firmar",
        opening_line_template=(
            "Los mensajes que salen de {domain} no llevan firma DKIM, que es lo que permite al "
            "servidor de destino comprobar que un correo es realmente vuestro."
        ),
    ),
    CatalogEntry(
        code="dkim-missing",
        lang="en",
        severity_rank=3,
        technical_description=(
            "No DKIM key is published at the declared selector for {domain}, so messages leave "
            "without a cryptographic signature and there is no way to show they were not "
            "altered in transit."
        ),
        plain_language_description=(
            "Email leaving {domain} is not signed. Without that signature the receiving server "
            "has no way to check the message is really yours, and treats it with more "
            "suspicion."
        ),
        subject_line_template="Email from {domain} is going out unsigned",
        opening_line_template=(
            "Messages leaving {domain} carry no DKIM signature, which is what lets the "
            "receiving server confirm an email is genuinely from you."
        ),
    ),
    # ---------------------------------------------------------------- rank 4
    CatalogEntry(
        code="spf-soft-all",
        lang="es",
        severity_rank=4,
        technical_description=(
            "El registro SPF de {domain} termina en ~all (softfail) o en +all, de modo que un "
            "servidor no autorizado que envíe en su nombre no es rechazado."
        ),
        plain_language_description=(
            "La política de correo de {domain} dice, literalmente, que quien no esté en la "
            "lista puede enviar igualmente. Es una puerta abierta a que alguien suplante "
            "vuestro dominio."
        ),
        subject_line_template="La política de correo de {domain} permite la suplantación",
        opening_line_template=(
            "El registro SPF de {domain} termina de una forma que permite enviar en vuestro "
            "nombre a servidores que no están autorizados."
        ),
    ),
    CatalogEntry(
        code="spf-soft-all",
        lang="en",
        severity_rank=4,
        technical_description=(
            "The SPF record for {domain} ends in ~all (softfail) or +all, so an unauthorised "
            "server sending on its behalf is not rejected."
        ),
        plain_language_description=(
            "The mail policy for {domain} says, in so many words, that anyone not on the list "
            "may send anyway. It is an open door to somebody impersonating your domain."
        ),
        subject_line_template="{domain}'s mail policy permits spoofing",
        opening_line_template=(
            "The SPF record for {domain} ends in a way that lets servers you have not "
            "authorised send mail in your name."
        ),
    ),
    # ---------------------------------------------------------------- rank 5
    CatalogEntry(
        code="dmarc-none-no-rua",
        lang="es",
        severity_rank=5,
        technical_description=(
            "{domain} publica DMARC con p=none y sin dirección rua, de modo que ni se aplica "
            "ninguna política ni se reciben los informes agregados que dirían quién está "
            "enviando en su nombre."
        ),
        plain_language_description=(
            "{domain} tiene DMARC puesto, pero en modo observación y sin recoger los informes. "
            "Es decir: ni bloquea nada ni os enseña quién está enviando correo con vuestro "
            "nombre. Está el cartel, pero no hay nadie mirando."
        ),
        subject_line_template="{domain} tiene DMARC, pero no está viendo los informes",
        opening_line_template=(
            "{domain} publica un registro DMARC, pero configurado de forma que no bloquea nada "
            "ni os envía los informes que dirían quién está suplantando el dominio."
        ),
    ),
    CatalogEntry(
        code="dmarc-none-no-rua",
        lang="en",
        severity_rank=5,
        technical_description=(
            "{domain} publishes DMARC with p=none and no rua address, so no policy is enforced "
            "and none of the aggregate reports that would say who is sending on its behalf are "
            "received."
        ),
        plain_language_description=(
            "{domain} has DMARC in place, but in observation mode and with nobody collecting "
            "the reports. So it neither blocks anything nor shows you who is sending mail in "
            "your name. The sign is up, but nobody is reading it."
        ),
        subject_line_template="{domain} has DMARC, but you are not seeing the reports",
        opening_line_template=(
            "{domain} publishes a DMARC record, but set up in a way that blocks nothing and "
            "sends you none of the reports that would show who is impersonating the domain."
        ),
    ),
    # ---------------------------------------------------------------- rank 6
    CatalogEntry(
        code="mta-sts-missing",
        lang="es",
        severity_rank=6,
        technical_description=(
            "{domain} no publica una política MTA-STS, así que el cifrado del correo entrante "
            "puede degradarse a texto plano por un atacante situado en la red."
        ),
        plain_language_description=(
            "El correo que llega a {domain} puede viajar sin cifrar si alguien interfiere en el "
            "camino. Con MTA-STS publicado, el servidor que os escribe se niega a entregarlo "
            "sin cifrado."
        ),
        subject_line_template="El correo que llega a {domain} puede viajar sin cifrar",
        opening_line_template=(
            "{domain} no publica una política MTA-STS, que es lo que impide que el correo "
            "entrante se entregue sin cifrar cuando alguien interfiere en la conexión."
        ),
    ),
    CatalogEntry(
        code="mta-sts-missing",
        lang="en",
        severity_rank=6,
        technical_description=(
            "{domain} publishes no MTA-STS policy, so encryption of inbound mail can be "
            "downgraded to plain text by an attacker positioned on the network."
        ),
        plain_language_description=(
            "Mail arriving at {domain} can travel unencrypted if somebody interferes along the "
            "way. With MTA-STS published, the server writing to you refuses to deliver it "
            "without encryption."
        ),
        subject_line_template="Mail arriving at {domain} can travel unencrypted",
        opening_line_template=(
            "{domain} publishes no MTA-STS policy, which is what stops inbound mail being "
            "delivered unencrypted when somebody interferes with the connection."
        ),
    ),
)

CATALOG_BY_KEY: dict[tuple[str, str], CatalogEntry] = {
    (entry.code, entry.lang): entry for entry in CATALOG
}

LANGS: tuple[str, ...] = ("es", "en")
