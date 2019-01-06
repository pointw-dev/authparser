# authparser
Used to parse http Authentication headers, and to call handlers per scheme.

Provides

### AuthParser
This class does the parsing and dispatches to handler methods per scheme.

`add_handler(scheme, user_record_fn, challenge_fn=None, **kwargs)`
- Registers an authentication scheme to be handled, and is details
  - **scheme**: (string) the name of the auth scheme, e.g. Basic, Bearer, Digest, etc.
  - **user_record_fn** (callable) the function `get_user_record()` calls after parsing the Authorization header.
    - The function will receive either the token for this scheme, or the params (see RFC 7235).
    - The function can return whatever your application needs, eg. True or False whether the Authoriation is valid, or a whole dict of claims.  `get_user_record()` merely passes what is returned back to your application.  
  - **challenge_fn** (callable) [optional] if specified, `get_challenge_header()` will call this function while building the `WWW-Authenticate` header. 
    - The function receives all kwargs passed to `get_challenge_header()`.  
    - The function should return a dict of name-value pairs which will be added to the scheme's challenge params.  e.g. a Digest challenge (without qop) will issue a challenge similar to: `WWW-Authenticate: Digest nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", realm="pointw.com", opaque="5ccc069c403ebaf9f0171e9517f40e41"`
  - **kwargs** - if any, they are passed through to the handler function.  For example, you may wish to pass the URL being requested, the method being used, or even the entire request object.


`clear_handlers()`
- Clears all handlers.

`get_user_record(auth_header)`
- Parses the Authorization header and passes the results to the handler for the corresponding scheme.
  - **auth_header** (string) the Authorization header from the request (with or without the starting `Authorization: ` keyword).

`get_challenge_header(**kwargs)`
- Returns the challenge header based on the handlers previously added.  Call this when forming the response to an unauthorized request.
  - **kwargs** [optional] 
    - set `multi_line=True` to have this method return an array of headers, one item in the array per scheme/handler.
    - all other kwargs are passed to the `challenge_fn` for it to use as it sees fit.  For example, if the request had an `Authorization:` header that had bad credentials, you could pass that fact to the `get_challenge_header()` so it can add details to the challenge header params. e.g. `WWW-Authenticate: Bearer error="invalid_token"`
