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
 *  2. Navigate to this URL to authenticate and get data from the API (state must be random and known by PHP):
 *     https://sim.logonvalidation.net/authorize?client_id=faf2acbb48754413a043676b9c2c2bd5&response_type=code&state=12345&redirect_uri=http%3A%2F%2Flocalhost%2Fopenapi-samples-php%2Fauthentication%2Foauth2-code-flow%2Fdemonstrate-code-flow.php
 *
 */

// Load the file with the app settings:
require "server-config.php";

/**
 * Display the header of the HTML, including the link with CSRF token in the state.
 */
function printHeader() {
    $redirectUri = 'http://localhost/openapi-samples-php/authentication/oauth2-code-flow/no-curl-version/demonstrate-code-flow.php';
    if (isset($_SESSION['csrf'])) {
        $csrfToken = $_SESSION['csrf'];  // A CSRF (Cross Site Request Forgery) Token is a secret, unique and unpredictable value an application generates in order to protect CSRF vulnerable resources.
    } else {
        $csrfToken = rand();
        // Remember the CSRF token in the session, so it can be compared with the incoming state of a new redirect.
        $_SESSION['csrf'] = $csrfToken;
    }
    // The CSRF token is part of the state and passed as base64 encoded string.
    // https://auth0.com/docs/protocols/oauth2/oauth-state
    $state = base64_encode(json_encode(array(
        'data' => '[Something to remember]',
        'csrf' => $csrfToken
    )));
    // The link differs per session. You can create a permalink using a redirect to this variable link.
    $link = 'https://sim.logonvalidation.net/authorize?client_id=faf2acbb48754413a043676b9c2c2bd5&response_type=code&state=' . urlencode($state) . '&redirect_uri=' . urlencode($redirectUri);
    echo '<!DOCTYPE html><html lang="en"><head><title>Basic PHP redirect example on the code flow</title></head><body>';
    echo 'Initiate a sign in using this link:<br /><a href="' . $link . '">' . $link . '</a><br /><br /><br />';
}

/**
 * Display the footer of the HTML.
 */
function printFooter() {
    echo '</body></html>';
}

/**
 * Verify if no error was returned.
 */
function checkForErrors() {
    $error = filter_input(INPUT_GET, 'error', FILTER_SANITIZE_URL);
    $error_description = filter_input(INPUT_GET, 'error_description', FILTER_SANITIZE_URL);
    if ($error || $error_description) {
        // Something went wrong. Maybe the login failed?
        die('Error: ' . $error . ' ' . $error_description);
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
        die('Error: No state found - this is unexpected, so don\'t try to get the token.');
    }
    if (!$expectedCsrfToken) {
        die('Error: No saved state found in the session - this is unexpected, so don\'t try to get the token.');
    }
    $receivedStateObjectString = base64_decode($receivedState);
    $receivedStateObject = json_decode($receivedStateObjectString);
    if (json_last_error() == JSON_ERROR_NONE) {
        if ($receivedStateObject->csrf != $expectedCsrfToken) {
            die('Error: The generated csrfToken (' . $expectedCsrfToken . ') differs from the csrfToken in the state (' . $receivedStateObject->csrf . '). This can indicate a malicious request (or was the state set in a different session?). Stop further processing and redirect back to the authentication.');
        }
        echo 'CSRF token in the state parameter is available and expected, so the redirect is trusted and a token can be requested.<br />';
        echo 'Data submitted via the state: ' . $receivedStateObject->data . '<br />';
    } else {
        die('Error: Invalid state found - this is unexpected, so don\'t try to get the token.');
    }
}

/**
 * Create the context for the HTTP request, including SSL verification.
 */
function createRequestContext($method, $header, $data) {
    $http = array(
                'method' => $method,
                'header' => $header,
                'ignore_errors' => false
            );
    if ($method == 'POST' || $method == 'PUT') {
        $http['content'] = $data;
    }
    return stream_context_create(
        array(
            'http' => $http,
            'ssl' => array(
                // This Mozilla CA certificate store is downloaded from:
                // https://curl.haxx.se/docs/caextract.html
                // This bundle was generated at Tue Apr 26 03:12:05 2022 GMT.
                'cafile' => 'cacert-2022-04-26.pem',
                'verify_peer' => true,
                'verify_peer_name' => true
            )
        )
    );
}

/**
 * Request date from Saxo.
 */
function doRequest($url, $context) {
    $result = @file_get_contents($url, false, $context);
    if (!$result) {
        if ($http_response_header[0] == 'HTTP/1.1 201 Created' || $http_response_header[0] == 'HTTP/1.1 202 Accepted') {
            // No response is expected.
            return null;
        }
        die('Error: ' . error_get_last()['message'] . ' (' . $url . ')');
    }
    $responseJson = json_decode($result);
    if (json_last_error() == JSON_ERROR_NONE) {
        if (property_exists($responseJson, 'error')) {
            die('Error: <pre>' . $responseJson . '</pre>');
        }
        return $responseJson;
    } else {
        // Something bad happened, no JSON in response.
        die('Error: ' . $result . ' (' . $url . ')');
    }
}

/**
 * Return the bearer token
 */
function getToken() {
    global $configuration;
    $code = filter_input(INPUT_GET, 'code', FILTER_SANITIZE_URL);
    $header = array(
        'Content-Type: application/x-www-form-urlencoded'
    );
    $data = array(
        'client_id' => $configuration->appKey,
        'client_secret' => $configuration->appSecret,
        'grant_type' => 'authorization_code',
        'code' => $code
    );
    $context = createRequestContext('POST', $header, http_build_query($data));
    // If you are looking here, probably something is wrong.
    // Is PHP properly installed (including OpenSSL extension)?
    // Troubleshooting:
    //  You can follow these steps to see what is going wrong:
    //  1. Run PHP in development mode, with warnings displayed, by using the development.ini.
    //  2. Remove the @ before "file_get_contents".
    //  3. Echo the $result and exit with "die();":
    //     $result = file_get_contents($configuration->tokenEndpoint, false, $context);
    //     echo $result;
    //     die();
    echo 'Requesting token..<br />';
    $responseJson = doRequest($configuration->tokenEndpoint, $context);
    echo 'New token from code: <pre>' . json_encode($responseJson, JSON_PRETTY_PRINT) . '</pre><br />';
    return $responseJson;
}

/**
 * Request user data, usually the first request, to get the ClientKey.
 */
function getUserFromApi($accessToken) {
    global $configuration;
    $header = array(
        'Authorization: Bearer ' . $accessToken
    );
    $context = createRequestContext('GET', $header, null);
    echo 'Requesting user data from the API..<br />';
    $responseJson = doRequest($configuration->openApiBaseUrl . 'port/v1/users/me', $context);
    echo 'Response from /users endpoint: <pre>' . json_encode($responseJson, JSON_PRETTY_PRINT) . '</pre><br />';
}

/**
 * (Try to) set the TradeLevel to FullTradingAndChat.
 */
function setTradeSession($accessToken) {
    global $configuration;
    $header = array(
        'Authorization: Bearer ' . $accessToken,
        'Content-Type: application/json; charset=utf-8'  // This is different than the token request content!
    );
    $data = array(
        'TradeLevel' => 'FullTradingAndChat'
    );
    $context = createRequestContext('PUT', $header, json_encode($data));
    echo 'Elevating Trade Session using PUT..<br />';
    $responseJson = doRequest($configuration->openApiBaseUrl . 'root/v1/sessions/capabilities', $context);
    echo 'Elevation of session requested.<br />';
}

/**
 * Return the bearer token
 * @param string $refreshToken This argument must contain the refresh_token.
 */
function refreshToken($refreshToken) {
    global $configuration;
    $header = array(
        'Content-Type: application/x-www-form-urlencoded'
    );
    $data = array(
        'client_id' => $configuration->appKey,
        'client_secret' => $configuration->appSecret,
        'grant_type' => 'refresh_token',
        'refresh_token' => $refreshToken
    );
    $context = createRequestContext('POST', $header, http_build_query($data));
    echo 'Refreshing token..<br />';
    $responseJson = doRequest($configuration->tokenEndpoint, $context);
    echo 'New token from refresh: <pre>' . json_encode($responseJson, JSON_PRETTY_PRINT) . '</pre><br />';
    return $responseJson;
}

session_start();  // The CSRF token is stored in the session.
printHeader();
checkForErrors();
checkState();
$tokenObject = getToken();
getUserFromApi($tokenObject->access_token);
setTradeSession($tokenObject->access_token);
$tokenObject = refreshToken($tokenObject->refresh_token);
printFooter();
