// netlify/functions/auth.js
//
// Reemplaza el registro/login que antes vivía solo en localStorage.
// Antes de dejar registrarse o iniciar sesión, revisa en Netlify Blobs si
// ese correo tiene una compra/suscripción ACTIVA según lo que reportó
// Hotmart a través de hotmart-webhook.js. Si no tiene acceso activo, se
// rechaza — así ya no se puede entrar sin haber pagado.

const { getStore } = require('@netlify/blobs');
const crypto = require('crypto');

function hashPassword(password, salt) {
  return crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
}

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};

exports.handler = async (event) => {
  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 200, headers: CORS_HEADERS, body: '' };
  }

  if (event.httpMethod !== 'POST') {
    return {
      statusCode: 405,
      headers: CORS_HEADERS,
      body: JSON.stringify({ error: 'Method not allowed' }),
    };
  }

  let body;
  try {
    body = JSON.parse(event.body || '{}');
  } catch (err) {
    return {
      statusCode: 400,
      headers: CORS_HEADERS,
      body: JSON.stringify({ error: 'JSON inválido' }),
    };
  }

  const { action, email, password } = body;
  if (!action || !email || !password) {
    return {
      statusCode: 400,
      headers: CORS_HEADERS,
      body: JSON.stringify({ error: 'Faltan datos (correo o contraseña)' }),
    };
  }

  const key = email.toLowerCase().trim();
  const blobsConfig = {
    siteID: process.env.BLOBS_SITE_ID,
    token: process.env.BLOBS_TOKEN,
  };
  const accessStore = getStore({ name: 'hotmart-access', ...blobsConfig });
  const usersStore = getStore({ name: 'importacontent-users', ...blobsConfig });

  const access = await accessStore.get(key, { type: 'json' });

  if (!access || access.status !== 'active') {
    return {
      statusCode: 403,
      headers: CORS_HEADERS,
      body: JSON.stringify({
        error:
          'Este correo no tiene una suscripción activa de ImportaContent Pro en Hotmart. Usa el mismo correo con el que compraste.',
      }),
    };
  }

  if (action === 'register') {
    const existingUser = await usersStore.get(key, { type: 'json' });
    if (existingUser) {
      return {
        statusCode: 409,
        headers: CORS_HEADERS,
        body: JSON.stringify({ error: 'Ya existe una cuenta con este correo. Inicia sesión.' }),
      };
    }
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = hashPassword(password, salt);
    await usersStore.setJSON(key, {
      email: key,
      salt,
      hash,
      createdAt: new Date().toISOString(),
    });
    return {
      statusCode: 200,
      headers: CORS_HEADERS,
      body: JSON.stringify({ ok: true, email: key }),
    };
  }

  if (action === 'login') {
    const user = await usersStore.get(key, { type: 'json' });
    if (!user) {
      return {
        statusCode: 404,
        headers: CORS_HEADERS,
        body: JSON.stringify({ error: 'No existe una cuenta con este correo. Regístrate primero.' }),
      };
    }
    const hash = hashPassword(password, user.salt);
    if (hash !== user.hash) {
      return {
        statusCode: 401,
        headers: CORS_HEADERS,
        body: JSON.stringify({ error: 'Contraseña incorrecta.' }),
      };
    }
    return {
      statusCode: 200,
      headers: CORS_HEADERS,
      body: JSON.stringify({ ok: true, email: key }),
    };
  }

  return {
    statusCode: 400,
    headers: CORS_HEADERS,
    body: JSON.stringify({ error: 'Acción no reconocida' }),
  };
};
