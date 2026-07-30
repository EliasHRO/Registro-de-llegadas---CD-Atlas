import { verifyToken, getTokenFromRequest, json, CORS_HEADERS } from "../../lib/auth.js";

export async function onRequestOptions() {
  return new Response(null, { status: 204, headers: CORS_HEADERS });
}

export async function onRequestGet({ env }) {
  const fields = await env.TORRE_KV.get("formfields:custom", "json");
  return json(fields || []);
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
  if (!Array.isArray(data.fields)) return json({ error: "Formato inválido" }, 400);

  const clean = data.fields
    .map((f) => ({
      id: (f.id || "").trim(),
      label: (f.label || "").trim(),
      type: f.type === "tel" ? "tel" : "text",
      required: !!f.required
    }))
    .filter((f) => f.id && f.label);

  await env.TORRE_KV.put("formfields:custom", JSON.stringify(clean));
  return json({ ok: true, fields: clean });
}
