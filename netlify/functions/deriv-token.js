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
    console.error('DERIV_CLIENT_ID env var is not set');
    return {
      statusCode: 500,
      body: JSON.stringify({ error: 'server_misconfigured', message: 'DERIV_CLIENT_ID env var is not set' })
    };
  }

  let payload;
  try {
    payload = JSON.parse(event.body || '{}');
  } catch (err) {
    console.error('Failed to parse request body:', event.body);
    return { statusCode: 400, body: JSON.stringify({ error: 'invalid_json' }) };
  }

  const { code, code_verifier: codeVerifier, redirect_uri: redirectUri } = payload;

  console.log('Token exchange request:', {
    hasCode: !!code,
    hasCodeVerifier: !!codeVerifier,
    redirectUri: redirectUri
  });

  if (!code || !codeVerifier || !redirectUri) {
    console.error('Missing params:', { code: !!code, codeVerifier: !!codeVerifier, redirectUri: !!redirectUri });
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

    console.log('Deriv token endpoint responded:', response.status, JSON.stringify(data));

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
    console.error('Upstream error calling Deriv token endpoint:', err.message, err.stack);
    return {
      statusCode: 502,
      body: JSON.stringify({ error: 'upstream_error', message: err.message })
    };
  }
};
