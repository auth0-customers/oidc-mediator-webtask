var express = require('express');
var request = require("request");
var Joi = require('joi');
var jwt = require('jsonwebtoken');
var jwksClient = require('jwks-rsa');
var bodyParser = require('body-parser');

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
    } else {
      console.log('Secrets: ', req.webtaskContext.secrets);
    }
    next();
}

app.use(mockWebtaskContext);
app.use(bodyParser.json());

// These are the rules the /out/token endpoint will use to validate the query string parameters
var tokenEndpointValidationRules = {
	body:{
		grant_type: Joi.string().required(),
		client_id: Joi.string().required(),
		code_verifier: Joi.string().required(),
		code: Joi.string().required(),
		redirect_uri: Joi.string().required(),
		client_assertion: Joi.string().required(),
		client_assertion_type: Joi.string().required()
	}
};

var validate = function(rules) {
	return function(req, res, next) {
    const result = Joi.validate(req.body, rules.body);
		if (result.error) return next(result.error);
		next();
  };
};

// Example:
// 		localhost:8081/oauth/token
//			?client_id=2ZUIv0DyveQJ1F4JW1ycNLeRyC0YTVE6
// 			&code=97ToXLLuaQo6DdKu
// 			&code_verifier=l-WZTynD8AYCqOlAzCZCmRvRea6bG5x39y4RJs73HGQ
//	 		&redirect_uri=https://leandro-pelorosso-testing-0.us.webtask.io/auth0-authentication-api-debugger
//	 		&grant_type=authorization_code
app.post('/oauth/token', validate(tokenEndpointValidationRules), function (req, res, next) {
	console.log('here');
	// assertion attributes are being required, so this should always be true
	// but just in case they changed them to be optional (as originally was)
  console.log('req.body: ', req.body);
	if(req.body.client_assertion && req.body.client_assertion_type){

		var client_assertion_type = req.body.client_assertion_type;
		var client_assertion = req.body.client_assertion;

		// validate client assertion type (should match the one on the configuration)
		console.log('assertion: ', req.webtaskContext.secrets.CLIENT_ASSERTION_TYPE, client_assertion_type);
		if(req.webtaskContext.secrets.CLIENT_ASSERTION_TYPE != client_assertion_type){
			throw ("Invalid Assertion Type")};

		// decode client assertion
		var decoded_assertion = jwt.decode(client_assertion, {complete: true});
		if(!decoded_assertion) { throw ("Invalid Client Assertion "); }

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

			try {
				publicKey = Buffer.from(req.webtaskContext.secrets.CERT, 'base64');
			} catch(e) {
				console.error('Could not decode: ', e);
				throw e;
			}

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
		jwt.verify(client_assertion, publicKey, {
			audience: 'https://' + req.webtaskContext.secrets.TENANT_DOMAIN,
			subject: req.body.client_id,
			issuer: req.body.client_id }, function(err, decoded) {
			if(err) {
				console.error('Error verifying: ', err);
				return next(err);
      }

			// client assertion is verified, so proceed to exchange code for token.
			exchangeCode(req, function(err, response){
				if(err) {
					console.error('Error exchanging code: ', err);
					return next(err);
        }
				console.log(response);
				res.status(200).json(response);
			});
		});
	}

});

/** Performs the code exchange calling oauth/token endpoint in Auth0 **/
function exchangeCode(req, callback){
	var params = req.body;

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
		url: 'https://' + req.webtaskContext.secrets.TENANT_DOMAIN + '/oauth/token',
		json: request_body
	};

	// make the request
	request(options, function (error, response, body) {

		if(error) return callback(error, null);
		if(body.error) return callback(body, null);

		// if the request was succesfully, build the response
		var response = {
		  access_token: body.access_token,
		  acr: "https://verified.me/loa/can/auth/standard", // TODO: we will ignore acr for now
		  expires_in: body.expires_in,
		  id_token: body.id_token,
		  refresh_token: body.refresh_token,
		  token_type: body.token_type
		};

		// if we have an access token and scopes are defined
		if(body.access_token){
			var decoded = jwt.decode(body.access_token);
			console.log('decoded token: ', decoded);
			response.scope = (decoded && decoded.scope)? decoded.scope : "";
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

module.exports = app;