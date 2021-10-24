# Oauth2 Fundamentals


**OAuth2** is an open standard for authorization  specified in the OAuth 2.0 Authorization Framework.  
     The OAuth 2.0 specification defines an authorization protocol (*a protocol that is focused on what actors have access to — not who the actor is*). This is specifically geared towards allowing a resource owner (user, most likely) to grant third-party applications and websites access to resources (which could be just about anything). Think of use cases such as a mobile app that can post pictures to Facebook where you authorize the app access to Facebook once and, from that point onward you can simply post pictures from the app to Facebook. As an authorization protocol, the details of how authentications works are largely undefined; in fact, in some cases the details of how the credentials are passed from the Client or User to Identity Provider aren’t specifically defined (that leaves a lot of room for things to get a little weird or, at least, custom). OAuth defines four primary actors:

* **Resource owner (RO)**: The entity that can grant access to a protected resource exposed by an API.  Typically this is the end-user.    
* **Client**:   The mobile application, web site, and so on, that wants to access a protected resource on behalf of the resource owner.  
    * Confidential clients are clients which have the ability to maintain the confidentiality of the client_secret. Typically these clients are only applications that run on a server under the control of the developer, where the source code is not accessible to users. These types of applications are commonly referred to as “web apps,” since they are most often accessed by a web browser.  
    * Public clients cannot maintain the confidentiality of a client_secret, so the secret is not used for these apps. Both mobile apps and Javascript apps are considered public clients. Since anyone running a Javascript app can easily view the source code of the application, a secret would be visible there trivially. With mobile applications, the binary can be decompiled to extract strings.  
* **Authorization server (AS)**: The Security Token Service (STS) or OAuth server that issues tokens. The authorization server will typically have two primary URLs, one for the authorization request and one for applications to use to grant access tokens. These are usually something such as:
  * https://authorization-server.com/authorize
  * https://authorization-server.com/token
* **Resource server (RS)**: The server hosting the protected resources. This is the API you want to access.  Resource servers rely on some kind of information to decide whether access to a protected resource should be granted. For RESTful-based resource servers, that information is usually carried in a security token, typically sent as a bearer token along with every request to the server. Web applications that rely on a session to authenticate users usually store that information in the user’s session and retrieve it from there for each request.   

## Application Registration

In order to make any call to the Resource Server API and to request your OAuth 2.0 access token, you need to register an application. Registered OAuth applications are assigned a unique Client ID (client_id) and a unique Client Secret (client_secret). Make sure to store the Client Secret securely.

## Oauth2 Flows

The Oauth2 flows (also called grant types) are scenarios an API client performs to get an access token from the authorization server. OAuth 2.0 provides several flows suitable for different types of API clients. 

Using different grants types (or flows), the participants will interact to grant to the client apps limited access to the APIs you are building. As a result, the client app will obtain an Access Token that can be used to call the API on behalf of the user.

### Authorization code grant
The most commonly used flow used by traditional web apps with a server backend (server side rendering), which involves end-users and authorizing third-party applications to access that end-user’s resources without exposing the end-user’s credentials to the third-party application. The client application doesn’t need to store or even directly request any resource owner’s credentials. This is generally referred to as three-legged OAuth.

The flow includes the following steps: Authorization Request and Token Request:

* **Authorization Request** - In the first step, the client application directs a resource owner to the OAuth 2.0 authorization endpoint and includes the following query parameters:
  * response_type - Must be set to code.
  * client_id - The same unique identifier of the client you received from registration.
  * redirect_uri - The same URL you registered as Callback URL during the client registration. 
  * state - (optional) A string used to maintain state between the request and callback. The parameter is used to protect against Cross-Site Request Forgery (CSRF).          
  
   [https://oauth2/authorize?client_id=$CLIENT_ID & response_type=code & redirect_uri=$CLIENT_REDIRECT_URI & state=$STATE ](https://oauth2/authorize)

      <em>**NOTE: Outside of the OAuth2 spec, the authorization endpoint will redirect the user to some form of login workflow. This could be on the same identity provider (Authorization Server) or could be a different one that has a federation relationship with this Authorization Server. That federation relationship between our Authorization Server and the third-party IdP could be based upon SAML , OpenID Connect or other protocols.** </em>         

  Eventually, the user agent will be passed an authorization code. That authorization code will be passed to the Client via a browser redirect to the redirect_uri endpoint. This response from the authorization endpoint will look something like:  
  HTTP/1.1 302 Found Location: https://client.example.com/cb?code=SplxlOBeZQQYbYS6WxSbIA&state=xyz

* **Token Request** - The Client will use the authorization code in the following call to the token endpoint
  ```java
  POST /oauth2/token HTTP/1.1 
  Host: authorization-server.com 
  Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW 
  Content-Type: application/x-www-form-urlencoded 
  grant_type=authorization_code&code=SplxlOBeZQQYbYS6WxSbIA 
  &redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb<br> 
  ```

  Note: Every request to the OAuth 2.0 token endpoint requires client authentication.  To authenticate an application with the Authorization Server, use the standard Authorization header with the basic authentication scheme, where the username is the client_id and the password is the client_secret: Authorization: Basic Base64($CLIENT_ID:$CLIENT_SECRET)  

Authorization code grant diagram

![oauth-diagram-token-request](img/authorization-code-flow.png)

* The end user initiates the flow by clicking on a login link, button, or similar action. The application redirects the User Agent to the Identity Provider (authorization endpoint).  
* The   Identity Provider   redirects the user to the authentication workflow (most likely a series of screens) that is not defined in the scope of the spec .  
* If authentication of the end-user is successful and the user grants access to the requested resource, the   Identity Provider   returns an Authorization Code and redirects the user to the Client application .  
* The Client then exchanges this Authorization Code for an access token . From there, the access token can be used to access the desired Resource(s) on the Resource Server. If the access token is being used for repeated API access that doesn’t have any other type of session management (like a session cookie), then it can be used until it expires (this assumes no one-time use or similar policy on the token). When the access token expires, a refresh token (which would be cached on the Client) can be used to obtain a new access token. This grant is geared towards confidential clients (server-side application components or something else that can protect the client secret); although, it can be used with public clients such as SPA Web Apps or Mobile Apps.

Example ( Login with Google ):
![authorization-code-flow-google-example](img/authorization-code-flow-google-example.png)

### Implicit grant

This flow requires the client to retrieve an access token directly. It is useful in cases when the user’s credentials cannot be stored in the client code because they can be easily accessed by the third party. It is suitable for web, desktop, and mobile applications that do not include any server component. This is generally referred to as two-legged OAuth. Refresh tokens are not used with this Grant.  

* **Authorization Request** - In the first step, the client application directs a resource owner to the OAuth 2.0 authorization endpoint and includes the following query parameters:
  * response_type - Must be set to   token  .
  * client_id - The same unique identifier of the client you received from registration.
  * redirect_uri - The same URL you registered as Callback URL during the client registration.
  * scope -    A space delimited list of scopes, which indicates the access to the Resource Owner's data requested by the application.  
  * state - (optional) A string used to maintain state between the request and callback. The parameter is used to protect against Cross-Site Request Forgery (CSRF).   
https://oauth2/authorize?client_id=$CLIENT_ID&response_type=token&redirect_uri=$CLIENT_REDIRECT_URI&state=$STATE 

  Response: the response to the above request is sent to the redirect_uri. If the user approves the access request, the response contains an access token and the state parameter (if included in the request). For example: https://localhost/oauth_callback#access_token=19437jhj2781FQd44AzqT3Zg&token_type=Bearer&expires_in=3600

  Note: You’ll notice that the access_token and other details are passed to the Client as query parameters in an HTTP redirect— not as part of a response message body. 

Implicit grant diagram 1

![oauth-diagram-implicit-grant](img/Implicit_Flow.png)

Implicit grant diagram 2
![oauth-diagram-implicit-grant](img/oauth-diagram-implicit-grant.png)

Example ( Login with Google ):
![implicit-flow-google-example](img/implicit-flow-google-example.png)

### Resource owner password credentials (or just password) grant

The Resource Owner password credentials flow is also known as the username-password authentication flow. This flow can be used as a replacement for an existing login when the consumer already has the user’s credentials.   This grant involves the Client application asking for the username and password directly from the end-user rather than directing the user to a login page hosted by the Authorization Server (or other Identity Provider) like in the first two Grants.  It is also used to migrate existing clients using direct authentication schemes such as HTTP Basic or Digest authentication to OAuth by converting the stored credentials to an access token

* **Token Request** -  The Resource Owner Password Credentials flow requires only a single step, where your client application performs a POST request to the /oauth2/token token endpoint with the grant_type set to password and including the resource owner’s credentials, in order to obtain an access token  
  * ```java
    POST /oauth2/token HTTP/1.1 
    Host: authorization-server.com
    Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW 
    Content-Type: application/x-www-form-urlencoded 
    grant_type=  password & username=johndoe&password=A3ddj3w  
    ```
  Note: Every request to the OAuth 2.0 token endpoint requires client authentication. To authenticate an application with the Authorization Server, use the standard Authorization header with the basic authentication scheme, where the username is the client_id and the password is the client_secret: Authorization: Basic Base64($CLIENT_ID:$CLIENT_SECRET)  
  * After the Web server has obtained an access token, it can gain access to protected resources on the Resource Server by placing it in an Authorization: Bearer HTTP header:                                                                                                                                                                          GET /oauth/protected HTTP/1.1
Authorization: Bearer O91G451HZ0V83opz6udiSEjchPynd2Ss9
Host:   authorization-server.com  

Resource owner password credentials grant diagram

![oauth-diagram-resource-owner-password-credentials-flow](img/oauth-diagram-resource-owner-password-credentials-flow.png)

### Client Credentials grant

This Grant does not authenticate an end-user, it just authenticates the Client; similar to the Resource Owner Password Grant, it is not an interactive login. It can only be used by a confidential Client. This is what is known as two-legged OAuth. If validation of the client credentials is successful, then an access token is returned that represents the Client. This is a simple, yet effective, way of managing the authentication step when the authorization decision only depends upon the calling application and not the end user. The following diagram was adapted from the OAuth2 spec:

Client Credentials grant diagram

![oauth-diagram-client-credentials-flow](img/oauth-diagram-client-credentials-flow.png)


## Accessing protected resources 

To access protected resources, the resource owner needs to supply the Access Token in a format described in the industry-adopted standard OAuth 2.0: Bearer Token.To authenticate to the API, use the standard Authorization header using the Bearer authentication scheme to transmit the access token. The syntax for the Authorization header is shown below. 

Authorization: Bearer $ACCESS_TOKEN  
    After the Web server has obtained an access token, it can gain access to protected resources on the Resource Server by placing it in an Authorization: Bearer HTTP header: Authorization: Bearer HTTP header:                           

GET /oauth/protected HTTP/1.1
Authorization: Bearer O91G451HZ0V83opz6udiSEjchPynd2Ss9
Host: authorization-server.com

## OAuth2 Extension Grants 

The OAuth2 Core Spec defines a mechanism for defining Extension (additional) Grants that can be used within the OAuth2 Framework. The Assertion Framework for OAuth 2.0 Client Authentication and Authorization Grant specification builds on this to provide “a framework for the use of assertions with OAuth 2.0 in the form of a new client authentication mechanism and a new authorization grant type. Mechanisms are specified for transporting assertions during interactions with a token endpoint; general processing rules are also specified.” The Assertion Framework for OAuth 2.0 provides a “common framework for OAuth 2.0 to interwork with other identity systems using assertions and to provide alternative client authentication mechanisms.” The use of the word Assertions here basically means Bearer Tokens (JWT, SAML v2.0 Bearer Tokens, etc).  

* **JWT as the OAuth2 Access Token** - JWT Profile for Authorization Grants (JSON Web Token (JWT) Profile for OAuth 2.0 Client Authentication and Authorization Grants spec):This spec defines how to use JWT tokens as the authentication mechanism for requesting an OAuth2 access token or for client authentication. When being used for requesting an access token, the JWT most likely describes an end user that was authenticated with another Identity Provider (that supports JWT)    
* **SAML as the OAuth2 Access Token**  -   SAML 2.0 Bearer Assertion Profiles (Security Assertion Markup Language (SAML) 2.0 Profile for OAuth 2.0 Client Authentication and Authorization Grants spec): This specification defines how to use SAML2 Bearer Tokens as the authentication mechanism for requesting an OAuth2 access token or for client authentication. When being used for requesting an access token, the SAML Assertion most likely describes an end user that was authenticated with another Identity Provider that supports SAML2 Bearer Tokens

## OAuth2 JWT Flow

A JSON Web Token (JWT) is a JSON-based security token encoding that enables identity and security information to be shared across security domains.

**A JWT Token contains three parts: A header, a body and a signature.**

* The header contains the type of token and the hash algorithm used on the contents of the token. Ex :{   "alg": "HS256",   "typ": "JWT" }
* The body, also called the payload, contains identity claims about a user.   Primarily, there are three types of claims: reserved, public, and private claims. Reserved claims are predefined claims such as iss (issuer), exp (expiration time), sub (subject), aud (audience).In private claims, we can create some custom claims such as subject, role, and others. Any number of additional claims with other names can be added, though care must be taken to keep the JWT within the browser size limitations for URLs.
* The signature ensures that the token is not changed on the way. It is used by the recipient of a JWT to validate the integrity of the information contained in the JWT.
* JWTs can be signed using a secret (with the HMAC algorithm) or a public/private key pair using RSA. Ex :  HMACSHA256(   base64UrlEncode(header) + "." +   base64UrlEncode(payload),   secret)  

**Creating a JWT Bearer Token** - To create a JWT bearer token, perform the following steps:

1. Construct a JWT header in the following format:  {"alg":"RS256"}
1. Base64 url encode the JWT Header.
1. Create a JWT Claims Set, which conforms to the following rules:
    * “iss” (Issuer) Claim :  must be the OAuth client_id  or the remote access application for which the developer registered their certificate.
    * “aud” (Audience) Claim: the recipient(s) that the JWT is intended for. This value is highly application (context) specific.  
    * “exp” (Expiration Time) Claim: the expiration time of the JWT. It is a number containing a NumericDate value.  
    * “sub” (Subject) Claim: the principal that is described by the JWT. The claims in a JWT are normally statements about the subject.  
    * “nbf” (Not Before) Claim: the time before which the JWT is not valid. The claim is optional.  
    * “iat” (Issued At) Claim: the time at which the JWT was issued — determines age of the token. Typically, the same as the “nbf” claim.
    * “jti” (JWT ID) Claim: a unique identifier for the JWT from the generating Identity Provider.   
    * The JWT must be signed.
    * The JWT must conform with the general format rules specified here: http://tools.ietf.org/html/draft-jones-json-web-toke
1. Base64 url encode the JWT Claims Set
1. Create a new string from the encoded JWT header from step 2, and the encoded JWT Claims Set from step 4, and append them as follows:    Base64URLEncode(JWT Header) + . + Base64URLEncode(JWT Claims Set)
1. Sign the resulting string in step 5 . The signature must then be Base64 url encoded. The signature is then concatenated with a.character to the end of the Base64url representation of the input string. The result is the following JWT (line breaks added for clarity): {Base64url encoded header}. {Base64url encoded claim set}.

**JWT Signature**: To create the JWT signature you  take the encoded header, the encoded payload, a secret, the algorithm specified in the header and sign that. The algorithm is part of the JWT header, for example :

* RS256  (RSA Signature with SHA-256)   is an asymmetric algorithm which means that there are two keys: one public and one private (secret). Auth Server has the secret key, which is used to generate the signature, and the consumer of the * * JWT has the public key, which is used to validate the signature.
HS256   (HMAC with SHA-256)  is a symmetric algorithm which means that there is only one secret key, shared between the two parties. The same key is used both to generate the signature and to validate it. Special care should be taken in order for the key to remain confidential
* The most secure practice is to use RS256. Some of the reasons are:
  * With RS256 you are sure that only the holder of the private key Auth Server can sign tokens, while anyone can check if the token is valid using the public key.
  * Under HS256, if the secret key is compromised (e.g. by the application) you would have to re-deploy the API with the new secret.
  * With RS256 you can request a token that is valid for multiple audiences.
  * With RS256 you can implement key rotation without having to re-deploy the API with the new secret.






