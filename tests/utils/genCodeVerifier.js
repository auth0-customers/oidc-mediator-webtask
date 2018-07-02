var crypto = require('crypto');
var auth0 = require('auth0-js');
var dotenv = require('dotenv');

dotenv.config();

function base64URLEncode(str) {
  return str.toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

var verifier = base64URLEncode(crypto.randomBytes(32));

function sha256(buffer) {
  return crypto.createHash('sha256').update(buffer).digest();
}
var challenge = base64URLEncode(sha256(verifier));

console.log('Verifier: ', verifier);
console.log('Challenge: ', challenge);

var auth = new auth0.Authentication({
  domain: process.env.TENANT_DOMAIN,
  clientID: process.env.CLIENT_ID
});

var authUrl = auth.buildAuthorizeUrl({
  redirectUri: 'https://jwt.io',
  responseType: 'code',
  codeChallenge: challenge,
  codeChallengeMethod: 'S256',
  scope: 'openid email profile',
  state: 'some-nonce',
  audience: 'api'
});

console.log('authurl: ', authUrl);

