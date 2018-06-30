var express = require('express');
var request = require("request");
var validate = require('express-validation')
var Joi = require('joi');
var jwt = require('jsonwebtoken');
var jwksClient = require('jwks-rsa');
var pki = require('node-forge').pki

var app = express();

const AUTH0_TENANT = 'leandro-pelorosso-testing-0';
const CLIENT_ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
const CERT = `-----BEGIN CERTIFICATE-----
MIIEszCCA5ugAwIBAgIJAMr5XxfI9iL5MA0GCSqGSIb3DQEBBQUAMIGXMQswCQYD
VQQGEwJDQTELMAkGA1UECBMCT04xEDAOBgNVBAcTB1Rvcm9udG8xHzAdBgNVBAoT
FlNlY3VyZUtleSBUZWNobm9sb2dpZXMxHDAaBgNVBAMTE1ZNRSBBcHAgU2lnbmlu
ZyBLZXkxKjAoBgkqhkiG9w0BCQEWG2Zsb3Jpbi5iaXJzYW5Ac2VjdXJla2V5LmNv
bTAeFw0xNzAzMTMxNDUyMjNaFw0xODAzMTMxNDUyMjNaMIGXMQswCQYDVQQGEwJD
QTELMAkGA1UECBMCT04xEDAOBgNVBAcTB1Rvcm9udG8xHzAdBgNVBAoTFlNlY3Vy
ZUtleSBUZWNobm9sb2dpZXMxHDAaBgNVBAMTE1ZNRSBBcHAgU2lnbmluZyBLZXkx
KjAoBgkqhkiG9w0BCQEWG2Zsb3Jpbi5iaXJzYW5Ac2VjdXJla2V5LmNvbTCCASIw
DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANfdtm3LgAXftjR6Za/Asmnrmrhm
X0TCqUCRXZ2Ze4wFic1fA61ARc56mioJmfGiNE6WtBmozQ8kpR6TUaz1oOUgfmJ8
vIDBZMIEnLJIP0tFasm6Y81CjzciTnxy6D5JChEyRFIwOCWGjoKWOSrukgRIgEAq
4Zq5fqKYokIwNIIbv1JaaEJzo5A/zHB9IsUeEHoI2dPgx9eIGF2+WU6Ht40kSDkI
o3D3nCELOW1pqkpuQoU041ZNzPmzEo+8Ntg3ENoM8u8fdB6dInF//V+zB6Luk3YI
OBaUyIR8AB85TDsxbWRqyvWAjUhqa3RobJngDfsdtgwaBqGiJv5TCqeInn8CAwEA
AaOB/zCB/DAdBgNVHQ4EFgQUVIjJqdVySn6Nzr9v0x3wvhZzlRowgcwGA1UdIwSB
xDCBwYAUVIjJqdVySn6Nzr9v0x3wvhZzlRqhgZ2kgZowgZcxCzAJBgNVBAYTAkNB
MQswCQYDVQQIEwJPTjEQMA4GA1UEBxMHVG9yb250bzEfMB0GA1UEChMWU2VjdXJl
S2V5IFRlY2hub2xvZ2llczEcMBoGA1UEAxMTVk1FIEFwcCBTaWduaW5nIEtleTEq
MCgGCSqGSIb3DQEJARYbZmxvcmluLmJpcnNhbkBzZWN1cmVrZXkuY29tggkAyvlf
F8j2IvkwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQUFAAOCAQEAZnRTkm3sYhMx
xPUQ1LB5jYVV3TTZIoIg2d5suqw5eL3SeF4X12wXlaKnwTzBoej4K3c4xxwR1Gwd
sNvjY0w8XdAuw/n5+BdoOlN6MWE/O2vz8oSYzUBrq/JsWlpWbdvVsm+5d3MJJ4g4
g1b1nDfDJZJq/t80UUzgd7yoTNeEbYj2bT7cLkFtuqG4MkjzrB/mwsR57XnPGRGC
zY93eKixZtQtXUGFgb4Ez16ZVZ5LWk9YNH4RNDJVIh+Q1Eons5NYUB57O3Ma3t7g
0hJcglOiWcn/pgO3y4SqvSlirsZpUF9YGUwgcOIvi/tPQ7yz6irLJrGqVtXjB8TQ
wlXjkKt8LA==
-----END CERTIFICATE-----`;

// These are the rules the /out/token endpoint will use to validate the query string parameters
var tokenEndpointValidationRules = {
	query:{
		grant_type: Joi.string().required(),
		client_id: Joi.string().required(),
		code_verifier: Joi.string().required(),
		code: Joi.string().required(),
		redirect_uri: Joi.string().required(),
		client_assertion: Joi.string().required(),
		client_assertion_type: Joi.string().required()
	}
}

// Example: 
// 		localhost:8081/oauth/token
//			?client_id=2ZUIv0DyveQJ1F4JW1ycNLeRyC0YTVE6
// 			&code=97ToXLLuaQo6DdKu
// 			&code_verifier=l-WZTynD8AYCqOlAzCZCmRvRea6bG5x39y4RJs73HGQ
//	 		&redirect_uri=https://leandro-pelorosso-testing-0.us.webtask.io/auth0-authentication-api-debugger
//	 		&grant_type=authorization_code
app.post('/oauth/token', validate(tokenEndpointValidationRules), function (req, res, next) {

	// assertion attributes are being required, so this should always be true
	// but just in case they changed them to be optional (as originally was)
	if(req.query.client_assertion && req.query.client_assertion_type){

		var client_assertion_type = req.query.client_assertion_type;
		var client_assertion = req.query.client_assertion;

		// validate client assertion type (should match the one on the configuration)
		if(CLIENT_ASSERTION_TYPE != client_assertion_type){ throw ("Invalid Assertion Type")};

		// decode client assertion
		var decoded_assertion = jwt.decode(client_assertion, {complete: true});
		if(!decoded_assertion) { throw ("Invalid Client Assertion ")};

		// get jku and kid from header
		var jku = decoded_assertion.header.jku;
		var kid = decoded_assertion.header.kid;

		console.log("JKU from Request Object is: ", jku);
		console.log("KID from Request Object is: ", kid);

		// the public key we will use
		var publicKey = null;

		// verification will depend on jku and kid attributes
		if (!jku || !kid ) {

			console.log("Using locally defined CERT to verify JWT.");

			var cert = pki.certificateFromPem(CERT);
			publicKey = pki.publicKeyToPem(cert.publicKey);

		} else { // we will use the JWK to verify token

			console.log("Using JWK to verify JWT.");

			// create the jwks client
			var client = jwksClient({
			  jwksUri:  jku
			});

			// how to retrieve the signinig key
			publicKey = function(header, callback){
			  client.getSigningKey(header.kid, function(err, key) {
			  	if(err) return callback(err, null);
			    var signingKey = key.publicKey || key.rsaPublicKey;
			    callback(null, signingKey);
			  });
			}
		}

		// verify the token, using client id as audience and issuer			
		jwt.verify(client_assertion, publicKey, { audience: req.query.client_id, issuer: req.query.client_id }, function(err, decoded) {
			if(err) return next(err);

			// client assertion is verified, so proceed to exchange code for token.
			exchangeCode(req.query, function(err, response){
				if(err) return next(err);
				console.log(err);
				console.log(response);
				res.status(200).json(response);
			});
		});
	}

});


/** Performs the code exchange calling oauth/token endpoint in Auth0 **/
function exchangeCode(params, callback){

	// get parameters from query string
	var request_body = {
		grant_type: params.grant_type,
		client_id: params.client_id,
		code_verifier: params.code_verifier,
		code: params.code,
		redirect_uri: params.redirect_uri
	};

	// build the request to auth0
	var options = { 
		method: 'POST',
	  	url: 'https://' + AUTH0_TENANT + '.auth0.com/oauth/token',
	  	headers: { 'content-type': 'application/json' },
	  	body: request_body,
	  	json: true
	}

	// make the request
	request(options, function (error, response, body) {

		if(error) return callback(error, null);
		if(body.error) return callback(body, null);

		// if the request was succesfully, build the response
		var response = {
		  access_token: body.access_token,
		  //acr: "string", // TODO: we will ignore acr for now
		  expires_in: body.expires_in,
		  id_token: body.id_token,
		  refresh_token: body.refresh_token,
		  token_type: body.token_type
		}

		// if we have an access token and scopes are defined
		if(body.access_token){
			var decoded = jwt.decode(body.access_token);
			response.scope = (decoded.scope)? decoded.scope : "";
		}

		// callback with the response
		callback(null, response);
	});

}

// Error Handling
app.use(function (err, req, res, next) {
  if(err.name){
  	return res.status(401).send({ error: err })
  }
  res.status(500).send({ error: err })
});

// Create Server
var server = app.listen(8081, function () {

   var host = server.address().address
   var port = server.address().port

   console.log("Mediator listening at http://%s:%s", host, port)
});