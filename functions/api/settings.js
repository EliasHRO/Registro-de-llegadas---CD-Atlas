import { verifyToken, getTokenFromRequest, json, CORS_HEADERS } from "../../lib/auth.js";

export async function onRequestOptions() {
  return new Response(null, { status: 204, headers: CORS_HEADERS });
}

// GET: público — el check-in necesita leer la geocerca sin sesión
export async function onRequestGet({ env }) {
  const settings = await env.TORRE_KV.get("settings:config", "json");
  return json(settings || {});
}

export async function onRequestPost({ request, env }) {
  const auth = await verifyToken(getTokenFromRequest(request));
  if (!auth || auth.role !== "admin") return json({ error: "No autorizado" }, 403);

  let data;
  try {
    data = await request.json();
  } catch {
    return json({ error: "JSON inválido" }, 400);
  }
  await env.TORRE_KV.put("settings:config", JSON.stringify(data));
  return json({ ok: true });
}
