// netlify/functions/hotmart-webhook.js
//
// Recibe las notificaciones (webhook) que Hotmart envía cada vez que alguien
// compra, cancela, le rechazan el pago, etc. Verifica que el aviso venga
// realmente de Hotmart (usando el HOTMART_HOTTOK guardado como variable de
// entorno) y guarda en Netlify Blobs si ese correo tiene o no acceso activo.
//
// Esta información la lee después la función auth.js para decidir si un
// usuario puede registrarse / iniciar sesión en ImportaContent Pro.

const { getStore } = require('@netlify/blobs');

const GRANT_EVENTS = new Set([
  'PURCHASE_APPROVED',
  'PURCHASE_COMPLETE',
  'PURCHASE_COMPLETO',
]);

const REVOKE_EVENTS = new Set([
  'PURCHASE_CANCELED',
  'PURCHASE_CANCELLED',
  'PURCHASE_REFUNDED',
  'PURCHASE_CHARGEBACK',
  'PURCHASE_EXPIRED',
  'PURCHASE_PROTEST',
  'PURCHASE_DELAYED',
  'SUBSCRIPTION_CANCELLATION',
  'SUBSCRIPTION_CANCELED',
]);

function extractEmail(data) {
  return (
    data?.buyer?.email ||
    data?.subscriber?.email ||
    data?.subscription?.subscriber?.email ||
    null
  );
}

exports.handler = async (event) => {
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, body: 'Method not allowed' };
  }

  let payload;
  try {
    payload = JSON.parse(event.body || '{}');
  } catch (err) {
    return { statusCode: 400, body: 'JSON inválido' };
  }

  // --- 1. Verificar que el aviso venga realmente de Hotmart ---
  const receivedToken =
    payload.hottok ||
    event.headers?.['x-hotmart-hottok'] ||
    event.headers?.['X-HOTMART-HOTTOK'];

  const expectedToken = process.env.HOTMART_HOTTOK;

  if (!expectedToken) {
    console.error('Falta configurar HOTMART_HOTTOK en Netlify');
    return { statusCode: 500, body: 'Falta configuración del servidor' };
  }

  if (!receivedToken || receivedToken !== expectedToken) {
    console.warn('Webhook recibido con hottok inválido o ausente');
    return { statusCode: 401, body: 'No autorizado' };
  }

  // --- 2. Leer los datos del evento ---
  const data = payload.data || {};
  const eventType = payload.event || 'UNKNOWN';
  const email = extractEmail(data);
  const productName = data.product?.name || null;
  const productId = data.product?.id || null;

  if (!email) {
    console.log('Webhook sin email detectable:', JSON.stringify(payload));
    return { statusCode: 200, body: 'OK (sin email en el payload)' };
  }

  let status = 'unknown';
  if (GRANT_EVENTS.has(eventType)) status = 'active';
  else if (REVOKE_EVENTS.has(eventType)) status = 'canceled';

  // --- 3. Guardar el estado de acceso de ese correo ---
  const store = getStore({
    name: 'hotmart-access',
    siteID: process.env.BLOBS_SITE_ID,
    token: process.env.BLOBS_TOKEN,
  });
  const key = email.toLowerCase().trim();
  const existing = (await store.get(key, { type: 'json' })) || {};

  const record = {
    ...existing,
    email: key,
    productId,
    productName,
    lastEvent: eventType,
    status: status !== 'unknown' ? status : existing.status || 'unknown',
    updatedAt: new Date().toISOString(),
  };

  await store.setJSON(key, record);

  return {
    statusCode: 200,
    body: JSON.stringify({ ok: true, email: key, status: record.status }),
  };
};
