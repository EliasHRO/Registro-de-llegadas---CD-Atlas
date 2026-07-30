import { verifyToken, getTokenFromRequest, json, CORS_HEADERS, kvListByPrefix } from "../../lib/auth.js";

const EL_SALVADOR_OFFSET_MS = -6 * 60 * 60 * 1000;
const EDITABLE_FIELDS = ["provider", "driverName", "plate", "phone", "transportType", "customFields"];

function haversineMeters(lat1, lng1, lat2, lng2) {
  const R = 6371000;
  const toRad = (d) => (d * Math.PI) / 180;
  const dLat = toRad(lat2 - lat1);
  const dLng = toRad(lng2 - lng1);
  const a =
    Math.sin(dLat / 2) ** 2 +
    Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) * Math.sin(dLng / 2) ** 2;
  return R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
}

export async function onRequestOptions() {
  return new Response(null, { status: 204, headers: CORS_HEADERS });
}

// GET: requiere sesión — lo usa el panel de control
export async function onRequestGet({ request, env }) {
  const auth = await verifyToken(getTokenFromRequest(request));
  if (!auth) return json({ error: "No autorizado" }, 403);

  const kv = env.TORRE_KV;
  const keys = await kvListByPrefix(kv, "arrival:");
  const records = [];
  for (const key of keys) {
    const val = await kv.get(key, "json");
    if (val) records.push(val);
  }
  records.sort((a, b) => a.ts - b.ts);
  return json(records);
}

// POST: público — lo usa el formulario de check-in sin sesión
export async function onRequestPost({ request, env }) {
  let data;
  try {
    data = await request.json();
  } catch {
    return json({ error: "JSON inválido" }, 400);
  }

  const provider = (data.provider || "").trim();
  const driverName = (data.driverName || "").trim();
  const plate = (data.plate || "").trim();
  const phone = (data.phone || "").trim();
  const transportType = (data.transportType || "").trim();
  const validTypes = ["Contenedor", "Camión", "Otros"];
  const customFields = typeof data.customFields === "object" && data.customFields !== null ? data.customFields : {};

  if (!provider || !driverName || !plate || !phone) {
    return json({ error: "Faltan datos: proveedor, motorista, placa y teléfono son obligatorios" }, 400);
  }
  if (!validTypes.includes(transportType)) {
    return json({ error: "Tipo de transporte inválido" }, 400);
  }

  const kv = env.TORRE_KV;
  const settings = await kv.get("settings:config", "json");
  let geoDistance = typeof data.geoDistance === "number" ? data.geoDistance : null;

  if (settings && settings.geofenceEnabled && settings.geofenceLat != null && settings.geofenceLng != null) {
    if (typeof data.geoLat !== "number" || typeof data.geoLng !== "number") {
      return json({ error: "Se requiere verificar tu ubicación para registrarte" }, 403);
    }
    const dist = haversineMeters(data.geoLat, data.geoLng, settings.geofenceLat, settings.geofenceLng);
    geoDistance = Math.round(dist);
    if (dist > settings.geofenceRadius) {
      return json({ error: `Estás a ${Math.round(dist)} m del centro. Debes estar a menos de ${settings.geofenceRadius} m.` }, 403);
    }
  }

  const utcNow = new Date();
  const local = new Date(utcNow.getTime() + EL_SALVADOR_OFFSET_MS);
  const date = local.toISOString().slice(0, 10);
  const time = local.toISOString().slice(11, 16);

  const id = `arrival:${utcNow.getTime()}-${Math.random().toString(36).slice(2, 7)}`;
  const record = {
    id, provider, driverName, plate, phone, transportType, customFields,
    ts: utcNow.getTime(), date, time,
    status: "esperando", dispatchedAt: null,
    geoLat: typeof data.geoLat === "number" ? data.geoLat : null,
    geoLng: typeof data.geoLng === "number" ? data.geoLng : null,
    geoDistance
  };

  await kv.put(id, JSON.stringify(record));

  (async () => {
    try {
      if (settings && settings.webhookUrl) {
        await fetch(settings.webhookUrl, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ ...record, notifyEmail: settings.notifyEmail || "" })
        });
      }
    } catch {
      // silencioso
    }
  })();

  return json(record);
}

// PATCH: solo admin — cambia estado y/o edita datos
export async function onRequestPatch({ request, env }) {
  const auth = await verifyToken(getTokenFromRequest(request));
  if (!auth || auth.role !== "admin") return json({ error: "No autorizado" }, 403);

  let data;
  try {
    data = await request.json();
  } catch {
    return json({ error: "JSON inválido" }, 400);
  }
  if (!data.id) return json({ error: "Falta id" }, 400);

  const kv = env.TORRE_KV;
  const existing = await kv.get(data.id, "json");
  if (!existing) return json({ error: "Registro no encontrado" }, 404);

  if (data.status) {
    existing.status = data.status;
    existing.dispatchedAt = data.status === "despachado" ? Date.now() : null;
  }
  for (const key of EDITABLE_FIELDS) {
    if (data[key] !== undefined) existing[key] = data[key];
  }

  await kv.put(data.id, JSON.stringify(existing));
  return json(existing);
}

// DELETE: solo admin
export async function onRequestDelete({ request, env }) {
  const auth = await verifyToken(getTokenFromRequest(request));
  if (!auth || auth.role !== "admin") return json({ error: "No autorizado" }, 403);

  let data;
  try {
    data = await request.json();
  } catch {
    return json({ error: "JSON inválido" }, 400);
  }
  if (!data.id) return json({ error: "Falta id" }, 400);
  await env.TORRE_KV.delete(data.id);
  return json({ ok: true });
}
