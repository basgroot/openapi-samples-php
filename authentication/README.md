# Examples on retrieving and refreshing the authentication token

Examples on
   - [OAuth2 Code Flow](oauth2-code-flow/)
   - [OAuth2 Certificate Based Flow (only for certain Saxo partners)](oauth2-certificate-flow/)

The token is valid for 20 minutes.
For implicit flow you receive no refresh token, but the other authentication flows return a refresh token as well.

The refresh token is valid for 1 hour.
With this token you can request a new token.

This can be repeated for a long time, until:
- Customer decides to sign out from all open sessions. This is an option in SaxoTraderGO.
- Saxo has maintenance in the weekend and systems are down for more than one hour.
