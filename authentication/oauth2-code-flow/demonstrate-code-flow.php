<?php

/*
 *  This sample demonstrates the following:
 *    1. Get a token,
 *    2. Request data from the API,
 *    3. Refresh the token.
 *
 *  Steps:
 *  1. Copy this file to your webserver running PHP and make sure this file is listening to this URL:
 *     http://localhost/openapi-samples-php/authentication/oauth2-code-flow/demonstrate-code-flow.php
 *
 *  2. Navigate to the URL displayed on top of the page, sign in and get data from the API.
 *
 */

// Load the file with the app settings:
require "server-config.php";

/**
 * Display the header of the HTML, including the link with CSRF token in the state.
 * @param string $url The URL to display in the header.
 */
function printHeader($url) {
    echo '<!DOCTYPE html><html lang="en"><head><title>Basic PHP redirect example on the code flow</title></head><body>';
    echo 'Initiate a sign in using this link:<br /><a href="' . $url . '">' . $url . '</a><br /><br /><br />';
}

/**
 * Display the footer of the HTML.
 */
function printFooter() {
    echo '</body></html>';
}

/**
 * Generate a random string, using a cryptographically secure pseudorandom number generator (random_int)
 * A CSRF (Cross Site Request Forgery) Token is a secret, unique and unpredictable value an application generates in order to protect CSRF vulnerable resources.
 *
 * For PHP 7, random_int is a PHP core function
 * For PHP 5.x, depends on https://github.com/paragonie/random_compat
 * 
 * @param int $length      How many characters do we want?
 * @return string
 */
function generateRandomToken($length) {
    return bin2hex(random_bytes($length));
}

/**
 * Construct the URL for a new login.
 * @param string $csrfToken The token to verify the redirect origin.
 * @return string
 */
function generateUrl($csrfToken) {
    global $configuration;
    // The CSRF token is part of the state and passed as base64 encoded string.
    // https://auth0.com/docs/protocols/oauth2/oauth-state
    $state = base64_encode(json_encode(array(
        'data' => '[Something to remember]',
        'csrf' => $csrfToken
    )));
    // The link differs per session. You can create a permalink using a redirect to this variable link.
    return $configuration->authEndpoint . '?client_id=' . $configuration->appKey . '&response_type=code&state=' . urlencode($state) . '&redirect_uri=' . urlencode($configuration->redirectUri);
}

/**
 * Verify if no error was returned.
 */
function checkForErrors() {
    $error = filter_input(INPUT_GET, 'error', FILTER_SANITIZE_URL);
    $error_description = filter_input(INPUT_GET, 'error_description', FILTER_SANITIZE_URL);
    if ($error || $error_description) {
        // Something went wrong. Maybe the login failed?
        throw new Exception('Error: ' . $error . ' ' . $error_description);
    }
    echo 'No error found in the redirect URL, so we can validate the CSRF token in the state parameter.<br />';
}

/**
 * Verify the CSRF token.
 */
function checkState() {
    $receivedState = filter_input(INPUT_GET, 'state', FILTER_SANITIZE_URL);
    $expectedCsrfToken = $_SESSION['csrf'];
    if (!$receivedState) {
        throw new Exception('Error: No state found - this is unexpected, so don\'t try to get the token.');
    }
    if (!$expectedCsrfToken) {
        throw new Exception('Error: No saved state found in the session - this is unexpected, so don\'t try to get the token.');
    }
    $receivedStateObjectString = base64_decode($receivedState);
    $receivedStateObject = json_decode($receivedStateObjectString);
    if (json_last_error() == JSON_ERROR_NONE) {
        if ($receivedStateObject->csrf != $expectedCsrfToken) {
            throw new Exception('Error: The generated csrfToken (' . $expectedCsrfToken . ') differs from the csrfToken in the state (' . $receivedStateObject->csrf . '). This can indicate a malicious request (or was the state set in a different session?). Stop further processing and redirect back to the authentication.');
        }
        echo 'CSRF token in the state parameter is available and expected, so the redirect is trusted and a token can be requested.<br />';
        echo 'Data submitted via the state: ' . $receivedStateObject->data . '<br />';
    } else {
        throw new Exception('Error: Invalid state found - this is unexpected, so don\'t try to get the token.');
    }
}

/**
 * Initiate cURL.
 * @param string $url The endpoint to call.
 * @return object
 */
function configureCurl($url) {
    $ch = curl_init($url);
    // https://www.php.net/manual/en/function.curl-setopt.php
    curl_setopt_array($ch, [
        CURLOPT_FAILONERROR    => false,  // Required for HTTP error codes to be reported via call to curl_error($ch)
        CURLOPT_SSL_VERIFYPEER => true,  // false to stop cURL from verifying the peer's certificate.
        CURLOPT_CAINFO         => 'cacert-2022-04-26.pem',
        CURLOPT_SSL_VERIFYHOST => 2,  // 2 to verify that a Common Name field or a Subject Alternate Name field in the SSL peer certificate matches the provided hostname.
        CURLOPT_FOLLOWLOCATION => false,  // true to follow any "Location: " header that the server sends as part of the HTTP header.
        CURLOPT_RETURNTRANSFER => true  // true to return the transfer as a string of the return value of curl_exec() instead of outputting it directly.
    ]);
    if (defined('CURL_VERSION_HTTP2') && (curl_version()['features'] & CURL_VERSION_HTTP2) !== 0) {
        curl_setopt($ch, CURLOPT_HTTP_VERSION, CURL_VERSION_HTTP2);  // CURL_HTTP_VERSION_2_0 (attempt to use HTTP 2, when available)
    }
    return $ch;
}

/**
 * Request a token ($postData specifies code, or refresh type).
 * @param array $postData The data body to sent.
 * @return object
 */
function getTokenResponse($postData) {
    global $configuration;
    $ch = configureCurl($configuration->tokenEndpoint);
    curl_setopt_array($ch, array(
        CURLOPT_POST       => true,
        CURLOPT_POSTFIELDS => $postData
    ));
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    // If you are looking here, probably something is wrong.
    // Is PHP properly installed (including OpenSSL extension)?
    // Troubleshooting:
    //  You can follow these steps to see what is going wrong:
    //  1. Run PHP in development mode, with warnings displayed, by using the development.ini.
    //  2. Do a var_dump of all variables and exit with "die();"
    if ($httpCode != 201) {
        throw new Exception('Error ' . $httpCode . ' while getting a token.');
    }
    $responseJson = json_decode($response);
    if (json_last_error() == JSON_ERROR_NONE) {
        if (property_exists($responseJson, 'error')) {
            throw new Exception('Error: <pre>' . $responseJson . '</pre>');
        }
        echo 'New token received: <pre>' . json_encode($responseJson, JSON_PRETTY_PRINT) . '</pre><br />';
        return $responseJson;
    } else {
        // Something bad happened, no JSON in response.
        throw new Exception('Error: ' . $response . ' (' . $configuration->tokenEndpoint . ')');
    }
}

/**
 * Return the bearer token.
 * @return object
 */
function getToken() {
    global $configuration;
    $code = filter_input(INPUT_GET, 'code', FILTER_SANITIZE_URL);
    echo 'Requesting a token with the code from the URL..<br />';
    return getTokenResponse(
        array(
            'grant_type'    => 'authorization_code',
            'client_id'     => $configuration->appKey,
            'client_secret' => $configuration->appSecret,
            'code'          => $code
        )
    );
}

/**
 * Return an API response, if any.
 * @param string $accessToken Bearer token.
 * @param string $method      HTTP Method.
 * @param string $url         The endpoint.
 * @param object $data        Data to send via the body.
 * @return object
 */
function getApiResponse($accessToken, $method, $url, $data) {
    global $configuration;
    $ch = configureCurl($configuration->openApiBaseUrl . $url);
    $header = array(
        'Authorization: Bearer ' . $accessToken  // CURLOPT_XOAUTH2_BEARER is added in cURL 7.33.0. Available since PHP 7.0.7.
    );
    if ($data != null) {
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));  // The full data to post in a HTTP "POST" operation. This parameter can either be passed as a urlencoded string like 'para1=val1&para2=val2&...' or as an array with the field name as key and field data as value.
        $header[] = 'Content-Type: application/json; charset=utf-8';  // This is different than the token request content!
    }
    curl_setopt_array($ch, array(
        CURLOPT_CUSTOMREQUEST => $method,  // A custom request method to use instead of "GET" or "HEAD" when doing a HTTP request. This is useful for doing "DELETE" or other, more obscure HTTP requests. Valid values are things like "GET", "POST", "CONNECT" and so on; i.e.
        CURLOPT_HEADER        => true,  // true to include the header in the output.
        CURLOPT_HTTPHEADER    => $header  // An array of HTTP header fields to set, in the format array('Content-type: text/plain', 'Content-length: 100')
    ));
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);  // As of cURL 7.10.8, this is a legacy alias of CURLINFO_RESPONSE_CODE
    $header_size = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
    curl_close($ch);
    // Separate response header from body
    $headers = explode("\n", substr($response, 0, $header_size));
    $body = substr($response, $header_size);
    echo 'Response headers (contain info about rate limits and the x-correlation):<pre>';
    foreach ($headers as $header)  {
        echo $header ."\n";
    }
    echo '</pre>';
    if ($body == '') {
        if ($httpCode >= 200 && $httpCode < 300) {
            // No response body, but response code indicates success https://developer.mozilla.org/en-US/docs/Web/HTTP/Status#successful_responses
            return null;
        } else {
            throw new Exception('Error with response HTTP ' . $httpCode);
        }
    }
    $responseJson = json_decode($body);
    if (json_last_error() == JSON_ERROR_NONE) {
        return $responseJson;
    } else {
        // Something bad happened, no JSON in response.
        throw new Exception('Error: ' . $response . ' (' . $url . ')');
    }
}

/**
 * Request user data, usually the first request, to get the ClientKey.
 * @param string $accessToken Bearer token.
 */
function getUserFromApi($accessToken) {
    echo 'Requesting user data from the API..<br />';
    $responseJson = getApiResponse($accessToken, 'GET', '/port/v1/users/me', null);
    echo 'Response from /users endpoint: <pre>' . json_encode($responseJson, JSON_PRETTY_PRINT) . '</pre><br />';
}

/**
 * (Try to) set the TradeLevel to FullTradingAndChat.
 * @param string $accessToken Bearer token.
 */
function setTradeSession($accessToken) {
    $data = array(
        'TradeLevel' => 'FullTradingAndChat'
    );
    echo 'Elevating Trade Session using PUT..<br />';
    getApiResponse($accessToken, 'PUT', '/root/v1/sessions/capabilities', $data);
    echo 'Elevation of session requested.<br />';
}

/**
 * Return the bearer token
 * @param string $refreshToken This argument must contain the refresh_token.
 * @return object
 */
function refreshToken($refreshToken) {
    global $configuration;
    echo 'Requesting a new token with the refresh_token..<br />';
    return getTokenResponse(
        array(
            'grant_type'    => 'refresh_token',
            'client_id'     => $configuration->appKey,
            'client_secret' => $configuration->appSecret,
            'refresh_token' => $refreshToken
        )
    );
}

session_start();  // The CSRF token is stored in the session.
$newCsrfToken = generateRandomToken(24);
$urlForNewLogin = generateUrl($newCsrfToken);
printHeader($urlForNewLogin);
try {
    checkForErrors();
    checkState();
    $tokenObject = getToken();
    getUserFromApi($tokenObject->access_token);
    setTradeSession($tokenObject->access_token);
    $tokenObject = refreshToken($tokenObject->refresh_token);
    printFooter();
} catch (Exception $ex) {
    echo $ex;
} finally {
    // Store the new CSRF token in the session, so it can be compared with the incoming state of a new redirect.
    $_SESSION['csrf'] = $newCsrfToken;
}
