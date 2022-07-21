# OpenAPI PHP Sample Repository

This repository contains sample files demonstrating OpenAPI interactions in PHP.

Since this is only backend, we recommend to take a look at the more detailed (and also web based) samples of the [JavaScript repository](https://saxobank.github.io/openapi-samples-js/).

## Requirements

Samples run against Saxo's simulation environment and require an **access token** in order to function. Saxo provides 24-hour tokens on the [Developer Portal](https://www.developer.saxo/openapi/token/), which is the easiest way to get started. An account is required to generate a token, which can be created for free.

CURL is used for the samples. HTTP/2 when supported.

## Table of Contents

1. Authentication
   - [OAuth2 Code Flow for websites](authentication/oauth2-code-flow/)
   - [OAuth2 PKCE Flow for single page apps](authentication/oauth2-pkce-flow/)
   - [OAuth2 Certificate Based Flow (only for certain Saxo partners)](authentication/oauth2-certificate-flow/)
2. API requests
   - [Stock Orders](orders/)

Suggestions? Comments? Reach us via Github or [openapisupport@saxobank.com](mailto:openapisupport@saxobank.com).
