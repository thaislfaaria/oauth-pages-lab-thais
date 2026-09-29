import { parseCookies } from "../_shared/cookies.js";
import { sha256Base64Url } from "../_shared/crypto.js";

export async function onRequestGet(context) {
  const cookies = parseCookies(context.request);
  const sessionId = cookies["__Host-session"];

  if (!sessionId) {
    return Response.json(
      { error: "Não autenticado" },
      {
        status: 401,
        headers: {
          "Cache-Control": "no-store",
        },
      }
    );
  }

  const idHash = await sha256Base64Url(sessionId);
  const now = Math.floor(Date.now() / 1000);

  const result = await context.env.DB.prepare(
    `SELECT issuer, subject, email, display_name, expires_at
     FROM sessions
     WHERE id_hash = ?
       AND expires_at > ?`
  )
    .bind(idHash, now)
    .first();

  if (!result) {
    return Response.json(
      { error: "Sessão inválida ou expirada" },
      {
        status: 401,
        headers: {
          "Cache-Control": "no-store",
        },
      }
    );
  }

  return Response.json(
    {
      issuer: result.issuer,
      subject: result.subject,
      email: result.email,
      displayName: result.display_name,
    },
    {
      headers: {
        "Cache-Control": "no-store",
      },
    }
  );
}
