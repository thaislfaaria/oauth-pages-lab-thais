function decodeBase64Url(value) {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/")
    + "=".repeat((4 - (value.length % 4)) % 4);

  const binary = atob(padded);
  const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));

  return new TextDecoder().decode(bytes);
}

function decodeJwtPart(value) {
  return JSON.parse(decodeBase64Url(value));
}

export async function getOidcConfiguration() {
  const response = await fetch(
    "https://accounts.google.com/.well-known/openid-configuration"
  );

  if (!response.ok) {
    throw new Error("Falha ao obter configuração OIDC");
  }

  return response.json();
}

export async function validateGoogleIdToken(
  idToken,
  expectedClientId,
  expectedNonce
) {
  const parts = idToken.split(".");

  if (parts.length !== 3) {
    throw new Error("JWT inválido");
  }

  const header = decodeJwtPart(parts[0]);
  const payload = decodeJwtPart(parts[1]);

  if (header.alg !== "RS256") {
    throw new Error("Algoritmo inválido");
  }

  const configuration = await getOidcConfiguration();

  if (payload.iss !== configuration.issuer) {
    throw new Error("Emissor inválido");
  }

  if (payload.aud !== expectedClientId) {
    throw new Error("Audiência inválida");
  }

  const now = Math.floor(Date.now() / 1000);

  if (typeof payload.exp !== "number" || payload.exp <= now) {
    throw new Error("Token expirado");
  }

  if (typeof payload.iat !== "number" || payload.iat > now + 60) {
    throw new Error("iat inválido");
  }

  if (payload.nonce !== expectedNonce) {
    throw new Error("Nonce inválido");
  }

  const jwksResponse = await fetch(configuration.jwks_uri);

  if (!jwksResponse.ok) {
    throw new Error("Falha ao obter JWKS");
  }

  const jwks = await jwksResponse.json();

  const jwk = jwks.keys.find((key) => key.kid === header.kid);

  if (!jwk) {
    throw new Error("Chave pública não encontrada");
  }

  const publicKey = await crypto.subtle.importKey(
    "jwk",
    jwk,
    {
      name: "RSASSA-PKCS1-v1_5",
      hash: "SHA-256",
    },
    false,
    ["verify"]
  );

  const data = new TextEncoder().encode(`${parts[0]}.${parts[1]}`);

  const signatureBase64 = parts[2]
    .replace(/-/g, "+")
    .replace(/_/g, "/")
    + "=".repeat((4 - (parts[2].length % 4)) % 4);

  const signatureBinary = atob(signatureBase64);
  const signature = Uint8Array.from(
    signatureBinary,
    (char) => char.charCodeAt(0)
  );

  const valid = await crypto.subtle.verify(
    {
      name: "RSASSA-PKCS1-v1_5",
    },
    publicKey,
    signature,
    data
  );

  if (!valid) {
    throw new Error("Assinatura inválida");
  }

  if (!payload.sub) {
    throw new Error("Subject ausente");
  }

  return {
    subject: String(payload.sub),
    email: payload.email ?? null,
    displayName: payload.name ?? null,
  };
}
