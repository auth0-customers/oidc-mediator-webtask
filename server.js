var express = require('express');
var request = require("request");
var validate = require('express-validation')
var Joi = require('joi');
var jwt = require('jsonwebtoken');
var jwksClient = require('jwks-rsa');
var pki = require('node-forge').pki

var app = express();

function mockWebtaskContext(req, res, next) {
    // Mock `req.webtaskContext` for standalone servers
    if (!req.webtaskContext) {
        req.webtaskContext = {
            secrets: {
                TENANT_DOMAIN: process.env.TENANT_DOMAIN,
                CLIENT_ASSERTION_TYPE: process.env.CLIENT_ASSERTION_TYPE,
                CERT: process.env.CERT,
            }
        };
    }
    next();
}

app.use(mockWebtaskContext);

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
		if(req.webtaskContext.secrets.CLIENT_ASSERTION_TYPE != client_assertion_type){
			throw ("Invalid Assertion Type")};

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

			var cert = pki.certificateFromPem(req.webtaskContext.secrets.CERT);
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
			exchangeCode(req, function(err, response){
				if(err) return next(err);
				console.log(err);
				console.log(response);
				res.status(200).json(response);
			});
		});
	}

});


/** Performs the code exchange calling oauth/token endpoint in Auth0 **/
function exchangeCode(req, callback){
	var params = req.query

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
		url: req.webtaskContext.secrets.TENANT_DOMAIN + '/oauth/token',
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