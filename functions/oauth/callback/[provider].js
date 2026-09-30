import { getProvider } from "../../_shared/providers.js";
import { parseCookies, serializeCookie } from "../../_shared/cookies.js";
import { sha256Base64Url, randomBase64Url } from "../../_shared/crypto.js";
import { validateGoogleIdToken } from "../../_shared/oidc.js";

export async function onRequestGet(context) {
  const providerName = context.params.provider;
  const provider = getProvider(providerName);

  if (!provider) {
    return new Response("Provedor não encontrado", { status: 404 });
  }

  const env = context.env;
  const url = new URL(context.request.url);

  const error = url.searchParams.get("error");
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");

  if (error || !code || !state) {
    return new Response("Resposta OAuth inválida", { status: 400 });
  }

  const cookies = parseCookies(context.request);
  const transactionId = cookies["__Host-oauth-tx"];

  if (!transactionId) {
    return new Response("Transação OAuth ausente", { status: 400 });
  }

  const transactionHash = await sha256Base64Url(transactionId);

  const transaction = await env.DB.prepare(
    `SELECT provider, state_hash, nonce, code_verifier, expires_at
     FROM oauth_transactions
     WHERE id_hash = ?`
  )
    .bind(transactionHash)
    .first();

  if (!transaction) {
    return new Response("Transação OAuth inválida", { status: 400 });
  }

  if (transaction.provider !== providerName) {
    return new Response("Provedor inválido", { status: 400 });
  }

  const now = Math.floor(Date.now() / 1000);

  if (transaction.expires_at <= now) {
    return new Response("Transação OAuth expirada", { status: 400 });
  }

  const stateHash = await sha256Base64Url(state);

  if (stateHash !== transaction.state_hash) {
    return new Response("State inválido", { status: 400 });
  }

  await env.DB.prepare(
    `DELETE FROM oauth_transactions
     WHERE id_hash = ?`
  )
    .bind(transactionHash)
    .run();

  const baseUrl = env.PUBLIC_BASE_URL;
  const redirectUri = `${baseUrl}/oauth/callback/${providerName}`;

  let clientId;
  let clientSecret;

  if (providerName === "google") {
    clientId = env.GOOGLE_CLIENT_ID;
    clientSecret = env.GOOGLE_CLIENT_SECRET;
  } else if (providerName === "github") {
    clientId = env.GITHUB_CLIENT_ID;
    clientSecret = env.GITHUB_CLIENT_SECRET;
  }

  if (!clientId || !clientSecret) {
    return new Response("Credenciais do provedor não configuradas", {
      status: 500,
    });
  }

  const tokenResponse = await fetch(provider.tokenEndpoint, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Accept: "application/json",
    },
    body: new URLSearchParams({
      client_id: clientId,
      client_secret: clientSecret,
      code,
      redirect_uri: redirectUri,
      grant_type: "authorization_code",
      code_verifier: transaction.code_verifier,
    }),
  });

  if (!tokenResponse.ok) {
    const tokenError = await tokenResponse.text();

    return new Response(
      `Falha ao trocar código OAuth: ${tokenResponse.status} ${tokenError}`,
      {
        status: 502,
      }
    );
  }

  const tokens = await tokenResponse.json();

  if (!tokens.access_token) {
    return new Response("Access token ausente", {
      status: 502,
    });
  }

  let identity;

  if (providerName === "google") {
    if (!tokens.id_token) {
      return new Response("ID token ausente", {
        status: 502,
      });
    }

    identity = await validateGoogleIdToken(
      tokens.id_token,
      clientId,
      transaction.nonce
    );
  }

  if (providerName === "github") {
    const userResponse = await fetch("https://api.github.com/user", {
      headers: {
        Authorization: `Bearer ${tokens.access_token}`,
        Accept: "application/vnd.github+json",
        "X-GitHub-Api-Version": "2026-03-10",
        "User-Agent": "oauth-pages-lab-thais",
      },
    });

    if (!userResponse.ok) {
      const userError = await userResponse.text();

      return new Response(
        `Falha ao obter usuário do GitHub: ${userResponse.status} ${userError}`,
        {
          status: 502,
        }
      );
    }

    const user = await userResponse.json();

    if (!Number.isInteger(user.id)) {
      return new Response("Identidade GitHub inválida", {
        status: 502,
      });
    }

    identity = {
      subject: String(user.id),
      email: user.email ?? null,
      displayName: user.name ?? user.login ?? null,
    };

    const revokeResponse = await fetch(
      `https://api.github.com/applications/${encodeURIComponent(clientId)}/grant`,
      {
        method: "DELETE",
        headers: {
          Authorization:
            "Basic " +
