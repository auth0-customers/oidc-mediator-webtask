# oidc-mediator-webtask

## Sample Call
```
curl -X POST \
  'http://localhost:8081/oauth/token?client_id=2ZUIv0DyveQJ1F4JW1ycNLeRyC0YTVE6&code=97ToXLLuaQo6DdKu&code_verifier=WZTynD8AYCqOlAzCZCmRvRea6bG5x39y4RJs73HGQ&redirect_uri=https://leandro-pelorosso-testing-0.us.webtask.io/auth0-authentication-api-debugger&grant_type=authorization_code&client_assertion=%27%27&client_assertion_type=%27%27' \
  -H 'Cache-Control: no-cache' \
  -H 'Postman-Token: 66ab993f-b74d-43c7-bf17-e3f65108f13c'
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