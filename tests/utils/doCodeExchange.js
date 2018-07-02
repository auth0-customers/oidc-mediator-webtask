var jwt = require('jsonwebtoken');
var fs = require('fs');
var moment = require('moment');
var crypto = require('crypto');
var dotenv = require('dotenv');
var request = require('request');

dotenv.config();

var privateKey = fs.readFileSync('private.pem');

function base64URLEncode(str) {
  return str.toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

var jti = base64URLEncode(crypto.randomBytes(32));
var payload = {
  iss: process.env.CLIENT_ID,
  sub: process.env.CLIENT_ID,
  aud: 'https://' + process.env.TENANT_DOMAIN,
  jti: jti,
  exp: parseInt(moment().unix()) + 300
};
console.log('Payload: ', payload);
var token = jwt.sign(payload, privateKey, { algorithm: 'RS256'});

console.log('Token: ', token);
console.log('argv: ', process.argv);
var baseUrl = process.argv[2];
var code = process.argv[4];
var verifier = process.argv[3];

var data = {
  client_id: process.env.CLIENT_ID,
  code: code,
  code_verifier: verifier,
  redirect_uri: 'https://jwt.io',
  grant_type: 'authorization_code',
  client_assertion: token,
  client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
};

request.post({
  url: baseUrl+'/oauth/token',
  json: data
}, function(err, res, body) {
  if (err) console.error(err);
  console.log('Body: ', body);
  console.log('Body: ', JSON.stringify(body));
});