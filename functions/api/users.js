import { hashPassword, makeSalt, verifyToken, getTokenFromRequest, json, CORS_HEADERS, kvListByPrefix } from "../../lib/auth.js";

async function requireAdmin(request) {
  const auth = await verifyToken(getTokenFromRequest(request));
  if (!auth || auth.role !== "admin") return null;
  return auth;
}

export async function onRequestOptions() {
  return new Response(null, { status: 204, headers: CORS_HEADERS });
}

export async function onRequestGet({ request, env }) {
  const auth = await requireAdmin(request);
  if (!auth) return json({ error: "No autorizado" }, 403);

  const kv = env.TORRE_KV;
  const keys = await kvListByPrefix(kv, "user:");
  const users = [];
  for (const key of keys) {
    const u = await kv.get(key, "json");
    if (u) users.push({ username: u.username, role: u.role, createdAt: u.createdAt });
  }
  users.sort((a, b) => a.username.localeCompare(b.username));
  return json(users);
}

export async function onRequestPost({ request, env }) {
  const auth = await requireAdmin(request);
  if (!auth) return json({ error: "No autorizado" }, 403);

  let data;
  try {
    data = await request.json();
  } catch {
    return json({ error: "JSON inválido" }, 400);
  }
  const kv = env.TORRE_KV;
  const username = (data.username || "").trim().toLowerCase();
  const password = data.password || "";
  const role = data.role === "admin" ? "admin" : "viewer";

  if (!/^[a-z0-9._-]{3,30}$/.test(username)) {
    return json({ error: "El usuario debe tener 3-30 caracteres (letras, números, puntos o guiones)" }, 400);
  }
  if (password.length < 4) {
    return json({ error: "La contraseña debe tener al menos 4 caracteres" }, 400);
  }
  const existing = await kv.get(`user:${username}`, "json");
  if (existing) {
    return json({ error: `El usuario "${username}" ya existe. Elimínalo primero si quieres reemplazarlo.` }, 400);
  }

  const salt = makeSalt();
  await kv.put(`user:${username}`, JSON.stringify({
    username,
    passwordHash: await hashPassword(password, salt),
    salt,
    role,
    createdAt: Date.now()
  }));
  return json({ ok: true });
}

export async function onRequestDelete({ request, env }) {
  const auth = await requireAdmin(request);
  if (!auth) return json({ error: "No autorizado" }, 403);

  let data;
  try {
    data = await request.json();
  } catch {
    return json({ error: "JSON inválido" }, 400);
  }
  const username = (data.username || "").trim().toLowerCase();
  if (username === auth.username) {
    return json({ error: "No puedes eliminar tu propio usuario" }, 400);
  }
  await env.TORRE_KV.delete(`user:${username}`);
  return json({ ok: true });
}
