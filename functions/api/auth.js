import { hashPassword, verifyPassword, makeSalt, signToken, json, CORS_HEADERS, kvListByPrefix } from "../../lib/auth.js";

export async function onRequestOptions() {
  return new Response(null, { status: 204, headers: CORS_HEADERS });
}

export async function onRequestPost({ request, env }) {
  let data;
  try {
    data = await request.json();
  } catch {
    return json({ error: "JSON inválido" }, 400);
  }

  const kv = env.TORRE_KV;

  // Salvaguarda: si no existe ningún usuario con rol admin, se restaura user:admin.
  const userKeys = await kvListByPrefix(kv, "user:");
  let hasAdmin = false;
  for (const key of userKeys) {
    const u = await kv.get(key, "json");
    if (u && u.role === "admin") { hasAdmin = true; break; }
  }
  if (!hasAdmin) {
    const salt = makeSalt();
    await kv.put("user:admin", JSON.stringify({
      username: "admin",
      passwordHash: await hashPassword("Torre2026", salt),
      salt,
      role: "admin",
      createdAt: Date.now()
    }));
  }

  const username = (data.username || "").trim().toLowerCase();
  const password = data.password || "";
  if (!username || !password) {
    return json({ error: "Usuario y contraseña son obligatorios" }, 400);
  }

  const user = await kv.get(`user:${username}`, "json");
  if (!user) return json({ error: "Usuario o contraseña incorrectos" }, 401);

  const ok = await verifyPassword(password, user.salt, user.passwordHash);
  if (!ok) return json({ error: "Usuario o contraseña incorrectos" }, 401);

  const token = await signToken(user.username, user.role);
  return json({ token, username: user.username, role: user.role });
}
