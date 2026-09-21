// netlify/functions/client-email.js
//
// Stores and checks the "Client Port" email whitelist using Netlify Blobs
// (a small persistent key-value store built into Netlify — no external
// database needed). Anyone can add their own email via the app's Client
// Port screen; the Login button then checks the remembered email against
// this same store before starting the Deriv OAuth flow.

const { getStore } = require('@netlify/blobs');

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

exports.handler = async function (event) {
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, body: 'Method not allowed' };
  }

  let payload;
  try {
    payload = JSON.parse(event.body || '{}');
  } catch (err) {
    return { statusCode: 400, body: JSON.stringify({ error: 'invalid_json' }) };
  }

  const action = payload.action;
  const email = String(payload.email || '').trim().toLowerCase();

  if (!email || !EMAIL_RE.test(email)) {
    return { statusCode: 400, body: JSON.stringify({ error: 'invalid_email' }) };
  }

  let store;
  try {
    store = getStore('client-emails');
  } catch (err) {
    console.error('Failed to open Blobs store:', err.message);
    return { statusCode: 500, body: JSON.stringify({ error: 'store_unavailable', message: err.message }) };
  }

  try {
    if (action === 'add') {
      await store.set(email, JSON.stringify({ addedAt: Date.now() }));
      return { statusCode: 200, body: JSON.stringify({ ok: true }) };
    }

    if (action === 'check') {
      const record = await store.get(email);
      return { statusCode: 200, body: JSON.stringify({ authorized: !!record }) };
    }

    return { statusCode: 400, body: JSON.stringify({ error: 'unknown_action' }) };
  } catch (err) {
    console.error('Blobs operation failed:', err.message);
    return { statusCode: 500, body: JSON.stringify({ error: 'store_error', message: err.message }) };
  }
};
