export function parseCookies(request) {
  const header = request.headers.get("Cookie") || "";
  const cookies = {};

  for (const part of header.split(";")) {
    const index = part.indexOf("=");

    if (index === -1) continue;

    const name = part.slice(0, index).trim();
    const value = part.slice(index + 1).trim();

    cookies[name] = value;
  }

  return cookies;
}

export function serializeCookie(
  name,
  value,
  {
    maxAge,
    httpOnly = true,
    secure = true,
    sameSite = "Lax",
    path = "/",
  } = {}
) {
  const parts = [
    `${name}=${value}`,
    `Path=${path}`,
    `SameSite=${sameSite}`,
  ];

  if (httpOnly) parts.push("HttpOnly");
  if (secure) parts.push("Secure");
  if (maxAge !== undefined) parts.push(`Max-Age=${maxAge}`);

  return parts.join("; ");
}
