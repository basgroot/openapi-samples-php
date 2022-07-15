<html>
<head>
  <title>Basic PHP redirect example on the code flow</title>
</head>

<body>
Initiate a sign in using this link:<br /><a href="https://sim.logonvalidation.net/authorize?client_id=faf2acbb48754413a043676b9c2c2bd5&response_type=code&state=12345&redirect_uri=http%3A%2F%2Flocalhost%2Fopenapi-samples-php%2Fauthentication%2Foauth2-code-flow%2Fdemonstrate-code-flow.php">https://sim.logonvalidation.net/authorize?client_id=faf2acbb48754413a043676b9c2c2bd5&response_type=code&state=12345&redirect_uri=http%3A%2F%2Flocalhost%2Fopenapi-samples-php%2Fauthentication%2Foauth2-code-flow%2Fdemonstrate-code-flow.php</a><br />
(make sure the state is random).
<br /><br />

<?php

//ini_set('display_errors', 1);
//ini_set('display_startup_errors', 1);
//error_reporting(E_ALL);

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

function checkForErrors() {
    $error = filter_input(INPUT_GET, 'error', FILTER_SANITIZE_URL);
    $error_description = filter_input(INPUT_GET, 'error_description', FILTER_SANITIZE_URL);
    if ($error || $error_description) {
        // Something went wrong. Maybe the login failed?
        die('Error: ' . $error . ' ' . $error_description);
    }
    echo 'No error found in the redirect URL, so we can validate the CSRF token in the state parameter.<br />';
}

function checkState() {
    $received_state = filter_input(INPUT_GET, 'state', FILTER_SANITIZE_URL);
    $expected_state = '12345';  // This must be random for real applications!
    if (!$received_state) {
        die('Error: No state found - this is unexpected, so don\'t try to get the token.');
    }
    if ($received_state != $expected_state) {
        die('Error: The generated csrfToken (' . $expected_state . ') differs from the csrfToken in the response (' . $received_state . '). This can indicate a malicious request. Stop further processing and redirect back to the authentication.');
    }
    echo 'CSRF token in the state parameter is available and expected, so the redirect is trusted and a token can be requested.<br />';
}

function configureCurl() {
    $ch = curl_init();
    if (defined('CURL_VERSION_HTTP2') && (curl_version()['features'] & CURL_VERSION_HTTP2) !== 0) {
        curl_setopt($ch, CURLOPT_HTTP_VERSION, CURL_VERSION_HTTP2);  // CURL_HTTP_VERSION_2_0 (attempts HTTP 2)
    }
    // https://www.php.net/manual/en/function.curl-setopt.php
    curl_setopt_array($ch, [
        CURLOPT_FAILONERROR    => true,  // Required for HTTP error codes to be reported via call to curl_error($ch)
        CURLOPT_SSL_VERIFYPEER => true,  // false to stop cURL from verifying the peer's certificate.
        CURLOPT_CAINFO         => 'cacert-2022-04-26.pem',
        CURLOPT_SSL_VERIFYHOST => 2,  // 2 to verify that a Common Name field or a Subject Alternate Name field in the SSL peer certificate matches the provided hostname.
        CURLOPT_FOLLOWLOCATION => false,  // true to follow any "Location: " header that the server sends as part of the HTTP header.
        CURLOPT_RETURNTRANSFER => true  // true to return the transfer as a string of the return value of curl_exec() instead of outputting it directly.
    ]);
    return $ch;
}

function getTokenResponse($postData) {
    global $configuration;
    $ch = configureCurl();
    curl_setopt_array($ch, array(
        CURLOPT_URL        => $configuration->tokenEndpoint,
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
    //  2. Do a var_dump of all variables and exit with "die();":
    $responseJson = json_decode($response);
    if (json_last_error() == JSON_ERROR_NONE) {
        if (property_exists($responseJson, 'error')) {
            die('Error: <pre>' . $responseJson . '</pre>');
        }
        echo 'New token received: <pre>' . json_encode($responseJson, JSON_PRETTY_PRINT) . '</pre><br />';
        return $responseJson;
    } else {
        // Something bad happened, no JSON in response.
        die('Error: ' . $response . ' (' . $configuration->tokenEndpoint . ')');
    }
}

/**
 * Return the bearer token
 */
function getToken() {
    global $configuration;
    $code = filter_input(INPUT_GET, 'code', FILTER_SANITIZE_URL);
    echo 'Requesting a token with the code from the URL..<br />';
    return getTokenResponse(
        array(
            'client_id'     => $configuration->appKey,
            'client_secret' => $configuration->appSecret,
            'grant_type'    => 'authorization_code',
            'code'          => $code
        )
    );
}

function getApiResponse($accessToken, $method, $url, $data) {
    global $configuration;
    $ch = configureCurl();
    $header = array(
        'Authorization: Bearer ' . $accessToken
    );
    switch ($method) {
        case 'POST':
            curl_setopt($ch, CURLOPT_POST, true);
            curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
            $header[] = 'Content-Type: application/json; charset=utf-8';  // This is different than the token request content!
            break;
        case 'PUT':
            //curl_setopt($ch, CURLOPT_PUT, true);
            curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'PUT');
            curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
            $header[] = 'Content-Type: application/json; charset=utf-8';  // This is different than the token request content!
            break;
        case 'PATCH':
            //curl_setopt($ch, CURLOPT_PUT, true);
            curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'PATCH');
            curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
            $header[] = 'Content-Type: application/json; charset=utf-8';  // This is different than the token request content!
            break;
    }
    curl_setopt($ch, CURLOPT_HEADER, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, $header);
    curl_setopt($ch, CURLOPT_URL, $configuration->openApiBaseUrl . $url);
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $header_size = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
    curl_close($ch);
    // Separate response header from body
    $headers = explode("\n", substr($response, 0, $header_size));
    $body = substr($response, $header_size);
    echo 'Headers:<pre>';
    foreach ($headers as $header)  {
        echo $header ."\n";
    }
    echo '</pre>';
    if ($body == '') {
        if ($httpCode == 201 || $httpCode == 202) {
            // No response body
            return null;
        } else {
            die('Error with response HTTP ' . $httpCode);
        }
    }
    $responseJson = json_decode($body);
    if (json_last_error() == JSON_ERROR_NONE) {
        return $responseJson;
    } else {
        // Something bad happened, no JSON in response.
        die('Error: ' . $response . ' (' . $url . ')');
    }
}

function getUserFromApi($accessToken) {
    echo 'Requesting user data from the API..<br />';
    $responseJson = getApiResponse($accessToken, 'GET', 'port/v1/users/me', null);
    echo 'Response from /users endpoint: <pre>' . json_encode($responseJson, JSON_PRETTY_PRINT) . '</pre><br />';
}

function precheckOrder($accessToken) {
    $data = array(
        'TradeLevel' => 'FullTradingAndChat'
    );
    echo 'Updating user..<br />';
    $responseJson = getApiResponse($accessToken, 'POST', 'trade/v2/orders/precheck', $data);
    echo 'Elevation of session requested.<br />';
}

function setTradeSession($accessToken) {
    $data = array(
        'TradeLevel' => 'FullTradingAndChat'
    );
    echo 'Elevating Trade Session using PUT..<br />';
    $responseJson = getApiResponse($accessToken, 'PUT', 'root/v1/sessions/capabilities', $data);
    echo 'Elevation of session requested.<br />';
}

/**
 * Return the bearer token
 * @param string $refreshToken This argument must contain the refresh_token.
 */
function refreshToken($refreshToken) {
    global $configuration;
    $code = filter_input(INPUT_GET, 'code', FILTER_SANITIZE_URL);
    echo 'Requesting a new token with the refresh_token..<br />';
    return getTokenResponse(
        array(
            'client_id'     => $configuration->appKey,
            'client_secret' => $configuration->appSecret,
            'grant_type' => 'refresh_token',
            'refresh_token' => $refreshToken
        )
    );
}

checkForErrors();
checkState();
$tokenObject = getToken();
//precheckOrder($tokenObject->access_token);
getUserFromApi($tokenObject->access_token);
setTradeSession($tokenObject->access_token);
$tokenObject = refreshToken($tokenObject->refresh_token);

?>

</body>
</html>