# oidc-mediator-webtask

## Setup
```
npm i
```

## Setup Auth0
* Create an application in Auth0 as a Native App
    * allow callback url: `https://jwt.io`
* Create an API with an identifier: `api`

## How to test
* Copy .env.example to .env (or .webtask.env if you are installing as a webtask)
    * replace values in .env with your tenant, client_id and next generate a certificate to add
* Generate a certificate
```
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -outform PEM -pubout -out public.pem
cat public.pem| base64 | pbcopy # paste the results in the .env or .webtask.env, this is the public key
```
* Create PKCE verifier
```
node tests/utils/genCodeVerifier.js
```
* Keep track of the code verifier and code challenge for the next few steps
* Copy the authURL and open it in a browser
* Log in
* The code will be sent to `https://jwt.io`, you can find it in the URL, save that for the final exchange
* Perform the code exchange
```
node tests/utils/doCodeExchange.js http://localhost:8081 CODE_VERIFIER CODE_FROM_URL
```

## Deploying as a Webtask
To deploy the webtask you should first create a `.webtask.env` file specific to
this environment.  This file will be used to generate the WT secrets in the
following steps.

1. Build the Webtask Code
    ```
    npm run wt:build
    ```
1. Deploy to your Webtask environment
    ```
    wt create dist/oidc-mediator-webtask.extension.1.0.0.js -p <wt-profile> -n oidc-mediator --secrets .webtask.env
    ```
1. You can now perform the same test as above, but instead of using `http://localhost:8081`, put the whole webtask URL (e.g. `https://YOUR_WEBTASK_URL/api/run/YOUR_TENANT/oidc-mediator`