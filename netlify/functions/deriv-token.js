// netlify/functions/deriv-token.js
//
// Runs server-side on Netlify (never in the browser). Deriv's own docs
// require the authorization code to be exchanged for a token from a
// backend, so this function is that backend.
//
// Set DERIV_CLIENT_ID as an environment variable in your Netlify site
// settings (Site configuration -> Environment variables) — it's your
// app's public App ID from the Deriv dashboard. PKCE means no
// client_secret is needed for this exchange.

const DERIV_TOKEN_URL = 'https://auth.deriv.com/oauth2/token';

exports.handler = async function (event) {
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, body: 'Method not allowed' };
  }

  const DERIV_CLIENT_ID = process.env.DERIV_CLIENT_ID;

  if (!DERIV_CLIENT_ID) {
    return {
      statusCode: 500,
      body: JSON.stringify({ error: 'server_misconfigured', message: 'DERIV_CLIENT_ID env var is not set' })
    };
  }

  let payload;
  try {
    payload = JSON.parse(event.body || '{}');
  } catch (err) {
    return { statusCode: 400, body: JSON.stringify({ error: 'invalid_json' }) };
  }

  const { code, code_verifier: codeVerifier, redirect_uri: redirectUri } = payload;

  if (!code || !codeVerifier || !redirectUri) {
    return { statusCode: 400, body: JSON.stringify({ error: 'missing_params' }) };
  }

  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    client_id: DERIV_CLIENT_ID,
    code: code,
    code_verifier: codeVerifier,
    redirect_uri: redirectUri
  });

  try {
    const response = await fetch(DERIV_TOKEN_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString()
    });

    const data = await response.json();

    if (!response.ok) {
      return { statusCode: response.status, body: JSON.stringify(data) };
    }

    // Only pass through what the frontend actually needs.
    return {
      statusCode: 200,
      body: JSON.stringify({
        access_token: data.access_token,
        expires_in: data.expires_in,
        token_type: data.token_type
      })
    };
  } catch (err) {
    return {
      statusCode: 502,
      body: JSON.stringify({ error: 'upstream_error', message: err.message })
    };
  }
};
