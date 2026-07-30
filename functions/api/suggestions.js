import { verifyToken, getTokenFromRequest, json, CORS_HEADERS, kvListByPrefix } from "../../lib/auth.js";

export async function onRequestOptions() {
  return new Response(null, { status: 204, headers: CORS_HEADERS });
}

export async function onRequestPost({ request, env }) {
  const auth = await verifyToken(getTokenFromRequest(request));
  if (!auth) return json({ error: "No autorizado" }, 403);

  let data;
  try {
    data = await request.json();
  } catch {
    return json({ error: "JSON inválido" }, 400);
  }
  const message = (data.message || "").trim();
  if (!message) return json({ error: "Escribe tu sugerencia" }, 400);

  const kv = env.TORRE_KV;
  const id = `suggestion:${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;
  const record = { id, message, from: auth.username, ts: Date.now() };
  await kv.put(id, JSON.stringify(record));

  // Reenvío por webhook, sin bloquear la respuesta al usuario.
  (async () => {
    try {
      const settings = await kv.get("settings:config", "json");
      if (settings && settings.webhookUrl) {
        await fetch(settings.webhookUrl, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            type: "sugerencia",
            ...record,
            notifyEmail: settings.suggestionsEmail || settings.notifyEmail || ""
          })
        });
      }
    } catch {
      // silencioso
    }
  })();

  return json({ ok: true });
}

export async function onRequestGet({ request, env }) {
  const auth = await verifyToken(getTokenFromRequest(request));
  if (!auth || auth.role !== "admin") return json({ error: "No autorizado" }, 403);

  const kv = env.TORRE_KV;
  const keys = await kvListByPrefix(kv, "suggestion:");
  const items = [];
  for (const key of keys) {
    const v = await kv.get(key, "json");
    if (v) items.push(v);
  }
  items.sort((a, b) => b.ts - a.ts);
  return json(items);
}
