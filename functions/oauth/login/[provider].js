import { getProvider } from "../../_shared/providers.js";
import { randomBase64Url, sha256Base64Url } from "../../_shared/crypto.js";
import { serializeCookie } from "../../_shared/cookies.js";

export async function onRequestGet(context) {
  const providerName = context.params.provider;
  const provider = getProvider(providerName);

  if (!provider) {
    return new Response("Provedor não encontrado", { status: 404 });
  }

  const env = context.env;

  const baseUrl = env.PUBLIC_BASE_URL;

  if (!baseUrl) {
    return new Response("PUBLIC_BASE_URL não configurada", { status: 500 });
  }

  let clientId;

  if (providerName === "google") {
    clientId = env.GOOGLE_CLIENT_ID;
  } else if (providerName === "github") {
    clientId = env.GITHUB_CLIENT_ID;
  }

  if (!clientId) {
    return new Response("Client ID não configurado", { status: 500 });
  }

  const state = await randomBase64Url(32);
  const codeVerifier = await randomBase64Url(32);
  const stateHash = await sha256Base64Url(state);
  const transactionId = await randomBase64Url(32);
  const transactionHash = await sha256Base64Url(transactionId);

  let nonce = null;

  if (providerName === "google") {
    nonce = await randomBase64Url(32);
  }

  const expiresAt = Math.floor(Date.now() / 1000) + 600;

  await env.DB.prepare(
    `INSERT INTO oauth_transactions
     (id_hash, provider, state_hash, nonce, code_verifier, expires_at)
     VALUES (?, ?, ?, ?, ?, ?)`
  )
    .bind(
      transactionHash,
      providerName,
      stateHash,
      nonce,
      codeVerifier,
      expiresAt
    )
    .run();

  const redirectUri =
    `${baseUrl}/oauth/callback/${providerName}`;

  const url = new URL(provider.authorizationEndpoint);

  url.searchParams.set("client_id", clientId);
  url.searchParams.set("redirect_uri", redirectUri);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("state", state);
  url.searchParams.set("code_challenge", await sha256Base64Url(codeVerifier));
  url.searchParams.set("code_challenge_method", "S256");

  if (providerName === "google") {
    url.searchParams.set("scope", "openid email profile");
    url.searchParams.set("nonce", nonce);
  }

  const cookie = serializeCookie(
    "__Host-oauth-tx",
    transactionId,
    {
      maxAge: 600,
      httpOnly: true,
      secure: true,
      sameSite: "Lax",
      path: "/",
    }
  );

  return new Response(null, {
    status: 302,
    headers: {
      Location: url.toString(),
      "Set-Cookie": cookie,
      "Cache-Control": "no-store",
    },
  });
}
