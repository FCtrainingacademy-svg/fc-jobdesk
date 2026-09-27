// Email: sends through SMTP when configured. Every message is also kept in the
// outbox table so the office can copy links if email isn't set up yet.
const nodemailer = require("nodemailer");
const { q } = require("./db");

const { SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, MAIL_FROM } = process.env;
const enabled = !!(SMTP_HOST && SMTP_USER && SMTP_PASS);
const transport = enabled
  ? nodemailer.createTransport({
      host: SMTP_HOST,
      port: Number(SMTP_PORT || 465),
      secure: Number(SMTP_PORT || 465) === 465,
      auth: { user: SMTP_USER, pass: SMTP_PASS },
    })
  : null;

const esc = (s) => String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

function wrap(title, bodyHtml, button) {
  return `<!doctype html><html><body style="margin:0;background:#f2f5f8;font-family:Arial,Helvetica,sans-serif;color:#16202b">
<div style="max-width:560px;margin:0 auto;padding:24px 16px">
  <div style="font-weight:700;color:#0b4a7d;font-size:14px;letter-spacing:.06em;text-transform:uppercase">FC JobDesk</div>
  <div style="background:#fff;border:1px solid #d3dbe4;border-radius:10px;padding:20px;margin-top:10px">
    <h1 style="font-size:20px;margin:0 0 12px">${esc(title)}</h1>
    ${bodyHtml}
    ${button ? `<p style="margin:20px 0 4px"><a href="${esc(button.href)}" style="background:#0b4a7d;color:#fff;text-decoration:none;padding:12px 18px;border-radius:8px;font-weight:700;display:inline-block">${esc(button.label)}</a></p>
    <p style="font-size:12px;color:#56616f;word-break:break-all">Or open: ${esc(button.href)}</p>` : ""}
  </div>
  <p style="font-size:12px;color:#56616f">FC Training Academy · Ilford</p>
</div></body></html>`;
}

async function send(to, subject, title, bodyHtml, button) {
  const html = wrap(title, bodyHtml, button);
  const text = `${title}\n\n${bodyHtml.replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim()}${button ? `\n\n${button.label}: ${button.href}` : ""}`;
  const row = await q("INSERT INTO outbox (to_addr, subject, body, link) VALUES ($1,$2,$3,$4) RETURNING id", [to, subject, text, button?.href || null]);
  if (!enabled) return { sent: false };
  try {
    await transport.sendMail({ from: MAIL_FROM || SMTP_USER, to, subject, html, text });
    await q("UPDATE outbox SET sent=TRUE WHERE id=$1", [row.rows[0].id]);
    return { sent: true };
  } catch (e) {
    console.error("[mail] failed:", e.message);
    await q("UPDATE outbox SET error=$2 WHERE id=$1", [row.rows[0].id, e.message.slice(0, 300)]);
    return { sent: false, error: e.message };
  }
}

module.exports = { send, enabled, esc };
