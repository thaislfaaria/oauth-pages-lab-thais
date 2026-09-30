import { parseCookies, serializeCookie } from "../_shared/cookies.js";
import { sha256Base64Url } from "../_shared/crypto.js";

export async function onRequestPost(context) {
  const origin = context.request.headers.get("Origin");
  const baseUrl = context.env.PUBLIC_BASE_URL;

  if (origin !== baseUrl) {
    return new Response("Origem inválida", { status: 403 });
  }

  const cookies = parseCookies(context.request);
  const sessionId = cookies["__Host-session"];

  if (sessionId) {
    const sessionHash = await sha256Base64Url(sessionId);

    await context.env.DB.prepare(
      `DELETE FROM sessions
       WHERE id_hash = ?`
    )
      .bind(sessionHash)
      .run();
  }

  const clearCookie = serializeCookie(
    "__Host-session",
    "",
    {
      maxAge: 0,
      httpOnly: true,
      secure: true,
      sameSite: "Strict",
      path: "/",
    }
  );

  return new Response(null, {
    status: 302,
    headers: {
      Location: baseUrl,
      "Set-Cookie": clearCookie,
      "Cache-Control": "no-store",
    },
  });
}
