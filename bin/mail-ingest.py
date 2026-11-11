#!/usr/bin/python3 -I
# =============================================================================
# Mail Platform :: mail-ingest.py
# Pipe transport do Postfix (master.cf, serviço "mailingest"): recebe a
# mensagem RFC 5322 no stdin, sela assunto, snippet, headers, corpos e anexos
# com crypto_box_seal (X25519 + XSalsa20-Poly1305) usando a public_key do
# destinatário e grava tudo nas hypertables do TimescaleDB (Servidor 2).
#
# Nada é escrito em disco: a mensagem só existe em memória até ser selada.
#
#   mail-ingest.py --sender S --recipient R [--original-recipient O]
#                  [--client-address IP] [--queue-id ID]
#
# Configuração: /etc/mail-platform/ingest.conf (KEY='valor', gerado pelo
# deploy-mail-node.sh). Conexão PostgreSQL com TLS verify-full.
#
# Códigos de saída (sysexits) — interpretados pelo Postfix:
#   0  EX_OK          entregue
#   67 EX_NOUSER      destinatário inexistente/inativo (bounce 5.1.1)
#   73 EX_CANTCREAT   cota excedida (bounce 5.2.2)
#   75 EX_TEMPFAIL    erro transitório (banco fora, etc.): fica na fila
# A primeira linha do stderr começa com o status DSN (4.x.x / 5.x.x), que o
# Postfix usa no lugar do código de saída.
#
# Formato dos campos cifrados (idêntico a src/Crypto/ZeroKnowledgeVault.php):
#   0x01 || crypto_box_seal(plaintext, public_key)
# =============================================================================
import argparse
import datetime as dt
import email
import email.policy
import hashlib
import hmac
import html
import json
import os
import re
import sys
import syslog
import unicodedata
import uuid
from email.message import EmailMessage
from email.utils import getaddresses

EX_OK = 0
EX_USAGE = 64
EX_DATAERR = 65
EX_NOUSER = 67
EX_SOFTWARE = 70
EX_CANTCREAT = 73
EX_TEMPFAIL = 75

CONFIG_FILE = os.environ.get("MP_INGEST_CONFIG", "/etc/mail-platform/ingest.conf")
FORMAT_VERSION = b"\x01"
SNIPPET_CHARS = 120
THREAD_WINDOW_DAYS = 90
SPAM_SCORE_FOLDER = 6.0
SUBJECT_INDEX_LABEL = "mp-subject-v1|"
SUBJECT_PREFIX_RE = re.compile(r"^(?:re|res|fw|fwd|enc|aw|sv|antw|tr)\s*(?:\[\d+\])?\s*:\s*", re.IGNORECASE)
KV_RE = re.compile(r"^(MP_[A-Z0-9_]+)='([^']*)'$")
ADDRESS_RE = re.compile(r"^[^@\s<>]{1,64}@[^@\s<>]{1,255}$")


class IngestError(Exception):
    """Erro com status DSN e código sysexits associados."""

    def __init__(self, exit_code, dsn, message):
        super().__init__(message)
        self.exit_code = exit_code
        self.dsn = dsn


def log(msg, prio=syslog.LOG_INFO):
    syslog.syslog(prio, msg)


# -----------------------------------------------------------------------------
# Configuração
# -----------------------------------------------------------------------------
def load_config(path):
    cfg = {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                m = KV_RE.match(line.strip())
                if m:
                    cfg[m.group(1)] = m.group(2)
    except OSError as exc:
        raise IngestError(EX_TEMPFAIL, "4.3.5", f"configuração indisponível: {exc}") from exc
    required = ("MP_DB_HOST", "MP_DB_PORT", "MP_DB_NAME", "MP_DB_USER", "MP_DB_PASSWORD",
                "MP_DB_SSLROOTCERT", "MP_SUBJECT_HMAC_KEY")
    missing = [k for k in required if not cfg.get(k)]
    if missing:
        raise IngestError(EX_TEMPFAIL, "4.3.5", f"configuração incompleta: {', '.join(missing)}")
    import base64

    try:
        cfg["_hmac_key"] = base64.b64decode(cfg["MP_SUBJECT_HMAC_KEY"], validate=True)
    except ValueError as exc:
        raise IngestError(EX_TEMPFAIL, "4.3.5", "MP_SUBJECT_HMAC_KEY inválida") from exc
    if len(cfg["_hmac_key"]) != 32:
        raise IngestError(EX_TEMPFAIL, "4.3.5", "MP_SUBJECT_HMAC_KEY deve ter 32 bytes")
    cfg["_max_bytes"] = int(cfg.get("MP_MAX_MESSAGE_BYTES", "52428800"))
    return cfg


# -----------------------------------------------------------------------------
# Criptografia (PyNaCl / libsodium)
# -----------------------------------------------------------------------------
class Sealer:
    def __init__(self, public_key):
        from nacl.public import PublicKey, SealedBox

        if len(public_key) != 32:
            raise IngestError(EX_TEMPFAIL, "4.3.0", "public_key da conta inválida")
        self._box = SealedBox(PublicKey(bytes(public_key)))

    def seal(self, data):
        if data is None:
            return None
        if isinstance(data, str):
            data = data.encode("utf-8")
        return FORMAT_VERSION + self._box.encrypt(bytes(data))


def normalize_subject(subject):
    """Idêntica a ZeroKnowledgeVault::normalizeSubject()."""
    s = unicodedata.normalize("NFKC", subject or "")
    s = re.sub(r"\s+", " ", s).strip()
    while True:
        new = SUBJECT_PREFIX_RE.sub("", s, count=1).strip()
        if new == s:
            break
        s = new
    return s.lower()


def subject_hash(subject, account_id, hmac_key):
    """Idêntica a ZeroKnowledgeVault::subjectHash()."""
    account_key = hmac.new(hmac_key, (SUBJECT_INDEX_LABEL + str(account_id).lower()).encode("utf-8"),
                           hashlib.sha256).digest()
    return hmac.new(account_key, normalize_subject(subject).encode("utf-8"), hashlib.sha256).digest()


# -----------------------------------------------------------------------------
# Parsing MIME
# -----------------------------------------------------------------------------
_TAG_BLOCK_RE = re.compile(r"<(script|style|head)\b[^>]*>.*?</\1>", re.IGNORECASE | re.DOTALL)
_BREAK_RE = re.compile(r"<br\s*/?>|</p>|</div>|</li>|</tr>", re.IGNORECASE)
_TAG_RE = re.compile(r"<[^>]+>")


def html_to_text(markup):
    markup = _TAG_BLOCK_RE.sub(" ", markup)
    markup = _BREAK_RE.sub(" ", markup)
    return html.unescape(_TAG_RE.sub("", markup))


def make_snippet(body_plain, body_html):
    """Idêntica a ZeroKnowledgeVault::makeSnippet() (até 120 caracteres)."""
    text = body_plain
    if text is None or not text.strip():
        text = html_to_text(body_html) if body_html is not None else ""
    text = re.sub(r"\s+", " ", text).strip()
    return text[:SNIPPET_CHARS]


def safe_get_content(part):
    try:
        content = part.get_content()
    except (LookupError, ValueError, AssertionError, UnicodeError):
        payload = part.get_payload(decode=True) or b""
        charset = part.get_content_charset() or "utf-8"
        try:
            content = payload.decode(charset, errors="replace")
        except LookupError:
            content = payload.decode("utf-8", errors="replace")
    return content


def raw_headers(raw):
    """Bloco de headers original (bytes até a primeira linha em branco)."""
    for sep in (b"\r\n\r\n", b"\n\n"):
        idx = raw.find(sep)
        if idx != -1:
            return raw[:idx]
    return raw


def parse_message(raw):
    msg = email.message_from_bytes(raw, policy=email.policy.default)
    if not isinstance(msg, EmailMessage):
        raise IngestError(EX_DATAERR, "5.6.0", "mensagem ilegível")

    try:
        subject = str(msg.get("Subject", "") or "")
    except (ValueError, IndexError):
        subject = str(msg.get_all("Subject", [""])[0])
    subject = subject.replace("\r", " ").replace("\n", " ").strip()

    body_plain = body_html = None
    plain_part = html_part = None
    try:
        plain_part = msg.get_body(preferencelist=("plain",))
        html_part = msg.get_body(preferencelist=("html",))
    except (KeyError, ValueError):
        pass
    if plain_part is not None:
        body_plain = safe_get_content(plain_part)
    if html_part is not None:
        body_html = safe_get_content(html_part)
    if body_plain is None and body_html is None and not msg.is_multipart():
        body_plain = safe_get_content(msg)

    attachments = []
    body_parts = {id(p) for p in (plain_part, html_part) if p is not None}
    for part in _attachment_parts(msg, body_parts):
        if part.get_content_type() == "message/rfc822":
            content = part.as_bytes(policy=email.policy.SMTP)
            filename = part.get_filename() or "mensagem-anexada.eml"
        else:
            content = part.get_payload(decode=True)
            if content is None:
                continue
            filename = part.get_filename() or _default_name(part)
        cid = part.get("Content-ID")
        cid = str(cid).strip().strip("<>") if cid else None
        disposition = (part.get_content_disposition() or "").lower()
        attachments.append({
            "name": _clean_filename(filename),
            "mime": part.get_content_type(),
            "cid": cid,
            "inline": disposition == "inline" or (cid is not None and disposition != "attachment"),
            "content": content,
        })

    from_addrs = getaddresses([str(v) for v in msg.get_all("From", [])])
    header_from = from_addrs[0][1] if from_addrs else ""
    return {
        "msg": msg,
        "subject": subject,
        "body_plain": body_plain,
        "body_html": body_html,
        "attachments": attachments,
        "header_from": header_from,
    }


def _leaf_parts(part):
    """Folhas MIME; message/rfc822 é tratado como folha (anexo .eml)."""
    if part.get_content_type() == "message/rfc822" or not part.is_multipart():
        yield part
        return
    for sub in part.iter_parts():
        yield from _leaf_parts(sub)


def _attachment_parts(msg, body_parts):
    """Tudo que não é o corpo escolhido: anexos, imagens inline (cid), .eml."""
    if not msg.is_multipart():
        return
    for part in _leaf_parts(msg):
        if id(part) in body_parts:
            continue
        disposition = (part.get_content_disposition() or "").lower()
        if (part.get_content_maintype() == "text" and part.get_content_subtype() in ("plain", "html")
                and disposition != "attachment" and not part.get_filename() and not part.get("Content-ID")):
            continue  # variante alternativa do corpo (ex.: segundo text/plain)
        yield part


def _default_name(part):
    ext = {
        "text/plain": ".txt", "text/html": ".html", "text/calendar": ".ics", "image/png": ".png",
        "image/jpeg": ".jpg", "image/gif": ".gif", "application/pdf": ".pdf",
    }.get(part.get_content_type(), ".bin")
    return "anexo" + ext


def _clean_filename(name):
    name = unicodedata.normalize("NFC", str(name)).replace("\x00", "")
    name = name.replace("/", "_").replace("\\", "_").strip() or "anexo.bin"
    return name[:255]


# -----------------------------------------------------------------------------
# Resultado SPF / DKIM / DMARC / spam (cabeçalhos do Rspamd)
# -----------------------------------------------------------------------------
_AR_RE = {
    "spf": re.compile(r"\bspf=(\w+)", re.IGNORECASE),
    "dkim": re.compile(r"\bdkim=(\w+)", re.IGNORECASE),
    "dmarc": re.compile(r"\bdmarc=(\w+)", re.IGNORECASE),
}
_SPAMD_SCORE_RE = re.compile(r"\[\s*(-?\d+(?:\.\d+)?)\s*/\s*-?\d+(?:\.\d+)?\s*\]")
_SPAM_STATUS_SCORE_RE = re.compile(r"score=(-?\d+(?:\.\d+)?)", re.IGNORECASE)


def auth_results(msg):
    # O Rspamd remove Authentication-Results recebidos (remove = 1) e insere o
    # seu no topo: o primeiro header é o confiável.
    ar = msg.get_all("Authentication-Results") or []
    first = str(ar[0]) if ar else ""
    res = {}
    for key, rx in _AR_RE.items():
        m = rx.search(first)
        res[key] = bool(m and m.group(1).lower() == "pass")

    score = 0.0
    spamd = msg.get("X-Spamd-Result")
    status = msg.get("X-Spam-Status")
    m = _SPAMD_SCORE_RE.search(str(spamd)) if spamd else None
    if not m and status:
        m = _SPAM_STATUS_SCORE_RE.search(str(status))
    if m:
        score = max(-999.99, min(999.99, float(m.group(1))))
    flagged = str(msg.get("X-Spam", "")).strip().lower() == "yes" or str(status or "").strip().lower().startswith("yes")
    res["spam_score"] = round(score, 2)
    res["is_spam"] = flagged or score >= SPAM_SCORE_FOLDER
    return res


# -----------------------------------------------------------------------------
# Banco de dados
# -----------------------------------------------------------------------------
def connect(cfg):
    try:
        import psycopg2
    except ImportError as exc:
        raise IngestError(EX_TEMPFAIL, "4.3.0", "psycopg2 indisponível") from exc
    try:
        conn = psycopg2.connect(
            host=cfg["MP_DB_HOST"],
            port=int(cfg["MP_DB_PORT"]),
            dbname=cfg["MP_DB_NAME"],
            user=cfg["MP_DB_USER"],
            password=cfg["MP_DB_PASSWORD"],
            sslmode=cfg.get("MP_DB_SSLMODE", "verify-full"),
            sslrootcert=cfg["MP_DB_SSLROOTCERT"],
            connect_timeout=10,
            application_name="mail-ingest",
        )
    except psycopg2.Error as exc:
        raise IngestError(EX_TEMPFAIL, "4.4.3", f"banco indisponível: {exc.__class__.__name__}") from exc
    return conn


def normalize_recipient(addr):
    addr = (addr or "").strip().strip("<>").lower()
    if not ADDRESS_RE.match(addr):
        raise IngestError(EX_NOUSER, "5.1.3", "endereço de destinatário inválido")
    local, domain = addr.rsplit("@", 1)
    local = local.split("+", 1)[0]   # recipient_delimiter = +
    return f"{local}@{domain}"


def deliver(cfg, args, raw):
    import psycopg2
    from psycopg2 import Binary

    recipient = normalize_recipient(args.recipient)
    parsed = parse_message(raw)
    auth = auth_results(parsed["msg"])
    size = len(raw)

    sender = (parsed["header_from"] or args.sender or "MAILER-DAEMON").strip()[:255]
    received_at = dt.datetime.now(dt.timezone.utc)
    message_id = uuid.uuid4()

    conn = connect(cfg)
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT a.id, a.public_key FROM mail_accounts a "
                    "JOIN mail_domains d ON d.id = a.domain_id "
                    "WHERE lower(a.email) = %s AND a.active = TRUE AND d.active = TRUE LIMIT 1",
                    (recipient,),
                )
                row = cur.fetchone()
                if row is None:
                    raise IngestError(EX_NOUSER, "5.1.1", "destinatário inexistente ou inativo")
                account_id, public_key = row[0], bytes(row[1])

                # Reserva de cota atômica
                cur.execute(
                    "UPDATE mail_accounts SET used_bytes = used_bytes + %s "
                    "WHERE id = %s AND used_bytes + %s <= quota_bytes RETURNING used_bytes",
                    (size, account_id, size),
                )
                if cur.fetchone() is None:
                    raise IngestError(EX_CANTCREAT, "5.2.2", "caixa postal cheia (cota excedida)")

                s_hash = subject_hash(parsed["subject"], account_id, cfg["_hmac_key"])
                cur.execute(
                    "SELECT thread_id FROM messages WHERE account_id = %s AND subject_hash = %s "
                    "AND received_at > %s ORDER BY received_at DESC LIMIT 1",
                    (account_id, Binary(s_hash), received_at - dt.timedelta(days=THREAD_WINDOW_DAYS)),
                )
                trow = cur.fetchone()
                thread_id = trow[0] if trow else str(uuid.uuid4())

                sealer = Sealer(public_key)
                snippet = make_snippet(parsed["body_plain"], parsed["body_html"])
                headers_bytes = raw_headers(raw)
                folder = "SPAM" if auth["is_spam"] else "INBOX"

                cur.execute(
                    "INSERT INTO messages (received_at, message_id, account_id, thread_id, folder, "
                    "sender_address, recipient_address, subject_hash, encrypted_subject, encrypted_snippet, "
                    "encrypted_headers, encrypted_body_plain, encrypted_body_html, spf_pass, dkim_pass, "
                    "dmarc_pass, spam_score, is_read, is_starred, has_attachments, size_bytes) "
                    "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, FALSE, FALSE, %s, %s)",
                    (
                        received_at, str(message_id), account_id, thread_id, folder,
                        sender, recipient[:255], Binary(s_hash),
                        Binary(sealer.seal(parsed["subject"])),
                        Binary(sealer.seal(snippet)),
                        Binary(sealer.seal(headers_bytes)),
                        _bin_or_none(sealer.seal(parsed["body_plain"])),
                        _bin_or_none(sealer.seal(parsed["body_html"])),
                        auth["spf"], auth["dkim"], auth["dmarc"], auth["spam_score"],
                        bool(parsed["attachments"]), min(size, 2**31 - 1),
                    ),
                )

                for att in parsed["attachments"]:
                    meta = json.dumps(
                        {"v": 1, "name": att["name"], "cid": att["cid"], "inline": att["inline"]},
                        ensure_ascii=False, separators=(",", ":"),
                    )
                    cur.execute(
                        "INSERT INTO message_attachments (received_at, attachment_id, account_id, message_id, "
                        "encrypted_filename, encrypted_mime_type, encrypted_content, size_bytes) "
                        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
                        (
                            received_at, str(uuid.uuid4()), account_id, str(message_id),
                            Binary(sealer.seal(meta)), Binary(sealer.seal(att["mime"])),
                            Binary(sealer.seal(att["content"])), len(att["content"]),
                        ),
                    )
                del sealer
    except IngestError:
        raise
    except psycopg2.Error as exc:
        raise IngestError(EX_TEMPFAIL, "4.3.0", f"erro de banco: {exc.__class__.__name__}") from exc
    finally:
        conn.close()

    return {
        "account_id": account_id,
        "message_id": message_id,
        "folder": folder,
        "size": size,
        "attachments": len(parsed["attachments"]),
        "auth": auth,
    }


def _bin_or_none(value):
    from psycopg2 import Binary

    return Binary(value) if value is not None else None


# -----------------------------------------------------------------------------
# Entrada
# -----------------------------------------------------------------------------
def parse_args(argv):
    p = argparse.ArgumentParser(description="Pipe criptográfico do Postfix -> TimescaleDB")
    p.add_argument("--sender", default="")
    p.add_argument("--recipient", required=True)
    p.add_argument("--original-recipient", default="")
    p.add_argument("--client-address", default="")
    p.add_argument("--queue-id", default="-")
    return p.parse_args(argv)


def read_stdin(limit):
    data = sys.stdin.buffer.read(limit + 1)
    if len(data) > limit:
        raise IngestError(EX_CANTCREAT, "5.3.4", "mensagem maior que o limite permitido")
    if not data:
        raise IngestError(EX_DATAERR, "5.6.0", "mensagem vazia")
    return data


def main(argv=None):
    syslog.openlog("mail-ingest", syslog.LOG_PID, syslog.LOG_MAIL)
    try:
        args = parse_args(argv)
    except SystemExit:
        return EX_USAGE
    qid = re.sub(r"[^A-Za-z0-9]", "", args.queue_id or "-")[:32] or "-"
    try:
        cfg = load_config(CONFIG_FILE)
        raw = read_stdin(cfg["_max_bytes"])
        info = deliver(cfg, args, raw)
        a = info["auth"]
        log(
            f"{qid}: entregue (cifrado) conta={info['account_id']} msg={info['message_id']} "
            f"pasta={info['folder']} bytes={info['size']} anexos={info['attachments']} "
            f"spf={int(a['spf'])} dkim={int(a['dkim'])} dmarc={int(a['dmarc'])} spam={a['spam_score']}"
        )
        return EX_OK
    except IngestError as exc:
        prio = syslog.LOG_WARNING if exc.exit_code == EX_TEMPFAIL else syslog.LOG_NOTICE
        log(f"{qid}: {exc.dsn} {exc}", prio)
        sys.stderr.write(f"{exc.dsn} {exc}\n")
        return exc.exit_code
    except Exception as exc:  # noqa: BLE001 - nunca perder mensagem por bug: tempfail
        log(f"{qid}: erro interno {exc.__class__.__name__}: {exc}", syslog.LOG_ERR)
        sys.stderr.write("4.3.0 erro interno temporário\n")
        return EX_TEMPFAIL


if __name__ == "__main__":
    sys.exit(main())
