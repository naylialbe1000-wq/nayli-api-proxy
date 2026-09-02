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
  const accessStore = getStore('hotmart-access');
  const usersStore = getStore('importacontent-users');

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
