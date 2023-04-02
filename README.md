# discord-express-auth
A basic package to use discord oauth2 to authenticate users in express

Before being able to use the functionality, first the package has to be configured:

```javascript
DiscordAuth.configure({
    clientId: process.env.CLIENT_ID as string,
    clientSecret: process.env.CLIENT_SECRET as string,
    tokenSecret: process.env.TOKEN_SECRET as string,
    scope: 'identify guilds',
});
```
---

Then several things can be done

An authorization code can be retrieved (this is  an endpoint)

```javascript
app.get('/authorize', DiscordAuth.authorize);
```

This expects a (get) request with a `redirect_uri` queryParameter passed. 

---

Generating a jwt token based on an authorization token (this is an endpoint):

```javascript
app.get('/login', DiscordAuth.authCodeToJwtToken);
```

This will take a (get) request which contains a whitelisted redirect_uri for your discord application, and the authorization code with which you want to log in.

This will set a cookie `access_token` which is a jsonwebtoken encrypted with the tokenSecret specified in configure. This JWT token will store:

 - user id
 - user name
 - access_token for accessing discord api
 - refresh_token for refreshing access to the discord api.
 - scope access
 - token type (bearer)

The valid duration of the jwt token cannot yet be set and is current 93 days.

---

Identifying a user based on a jwt token (this is middleware) which will give access to all of the details stored in the Jsonwebtoken mentioned above.

```javascript
router.get('/id', DiscordAuth.identify, async (req: ISessionAuthRequest, res: Response) => {
  ...
}
```
---

reAuthorization can be done when a call to the discord api fails because the discord token timed out. (this is a custom function and neither middleware nor an endpoint.

```javascript
  ...
  if(discordApiRequest.statusCode === 401) {
    DiscordAuth.reAuth(request, response, next, currentFunction);
  }
  ...
```
This will attempt to update the access_token and refresh_token and then re-execute the function that is passed, which can be the current function.

If the discord authentication fails then it will close the response with a 401.

---

Log the user out (this is an endpoint)

```javascript
app.get('/logout', DiscordAuth.logout);
```
This will attempt to revoke both the access and refresh tokens with discord, and will clear the cookie in the response.
