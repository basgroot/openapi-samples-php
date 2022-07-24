<?php
header("Content-Type: text/plain");

$accessToken = '';
$openApiBaseUrl = 'https://gateway.saxobank.com/sim/openapi';

/**
 * Log request and response code/headers.
 * @param string $method         HTTP Method.
 * @param string $url            The endpoint.
 * @param object $data           Data to send via the body.
 * @param int $httpCode          HTTP response code.
 * @param array $responseHeaders The response headers, useful for request limits and correlation.
 * @return void
 */
function logRequest($method, $url, $data, $httpCode, $responseHeaders) {
    $xCorrelationHeader = 'x-correlation: ';
    $xCorrelation = '-';
    $xRateLimitAppDayRemainingHeader = 'x-ratelimit-appday-remaining: ';
    $xRateLimitAppDayRemaining = '';
    foreach ($responseHeaders as $header)  {
        if (strpos($header, $xCorrelationHeader) !== false) {
            $xCorrelation = substr($header, strlen($xCorrelationHeader));
        } else if (strpos($header, $xRateLimitAppDayRemainingHeader) !== false) {
            $xRateLimitAppDayRemaining = substr($header, strlen($xRateLimitAppDayRemainingHeader));
        }
    }
    $logLine = $httpCode . ' Request: ' . $method . ' ' . $url . ' x-correlation: ' . $xCorrelation;
    if ($xRateLimitAppDayRemaining !== '') {
        // On errors, this header is not sent to the client
        $logLine .= ' remaining requests today: ' . $xRateLimitAppDayRemaining;
    }
    if ($data != null) {
        $logLine .= ' body: ' . json_encode($data);
    }
    error_log($logLine);  // Location of this log can be found with ini_get('error_log')
    echo $logLine . "\n";
}

/**
 * Show a message for the user to indicate what happened.
 * @param object $error HTTP Method.
 * @return string
 */
function processErrorResponse($error) {
    if (isset($error->ErrorInfo)) {
        $error = $error->ErrorInfo;
    }
    $result = $error->Message;
    if (isset($error->ModelState)) {
        foreach ($error->ModelState as $modelState)  {
            $result .= "\n" . $modelState[0];
        }
    }
    /*
    {
        "ErrorCode": "IllegalInstrumentId",
        "Message": "Instrument-ID is ongeldig"
    }

    {
        "Message": "One or more properties of the request are invalid!",
        "ModelState": {
            "AssetType": [
                "'Asset Type' must not be empty."
            ],
            "OrderDuration": [
                "The specified condition was not met for 'Order Duration'."
            ]
        },
        "ErrorCode": "InvalidModelState"
    }
    */
    echo "\n" . json_encode($error, JSON_PRETTY_PRINT) . "\n";
    return $result;
}

/**
 * Call an endpoint of the OpenAPI.
 * @param string $method      HTTP Method.
 * @param string $url         The endpoint.
 * @param object $data        Data to send via the body.
 * @return object
 */
function getApiResponse($method, $url, $data) {
    global $openApiBaseUrl;
    global $accessToken;
    $ch = curl_init($openApiBaseUrl . $url);
    if (defined('CURL_VERSION_HTTP2') && (curl_version()['features'] & CURL_VERSION_HTTP2) !== 0) {
        curl_setopt($ch, CURLOPT_HTTP_VERSION, CURL_VERSION_HTTP2);  // CURL_HTTP_VERSION_2_0 (attempt to use HTTP 2, when available)
    }
    $header = array(
        'Authorization: Bearer ' . $accessToken  // CURLOPT_XOAUTH2_BEARER is added in cURL 7.33.0. Available since PHP 7.0.7.
    );
    if ($data != null) {
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));  // The full data to post in a HTTP "POST" operation. This parameter can either be passed as a urlencoded string like 'para1=val1&para2=val2&...' or as an array with the field name as key and field data as value.
        $header[] = 'Content-Type: application/json; charset=utf-8';  // This is different than the token request content!
    }
    // https://www.php.net/manual/en/function.curl-setopt.php
    curl_setopt_array($ch, array(
        CURLOPT_FAILONERROR    => false,  // Required for HTTP error codes to be reported via call to curl_error($ch)
        CURLOPT_SSL_VERIFYPEER => true,  // false to stop cURL from verifying the peer's certificate.
        CURLOPT_CAINFO         => __DIR__ . '/cacert-2022-07-19.pem',  // This Mozilla CA certificate store was generated at Tue Jul 19 03:12:06 2022 GMT and is downloaded from https://curl.haxx.se/docs/caextract.html
        CURLOPT_SSL_VERIFYHOST => 2,  // 2 to verify that a Common Name field or a Subject Alternate Name field in the SSL peer certificate matches the provided hostname.
        CURLOPT_FOLLOWLOCATION => false,  // true to follow any "Location: " header that the server sends as part of the HTTP header.
        CURLOPT_RETURNTRANSFER => true,  // true to return the transfer as a string of the return value of curl_exec() instead of outputting it directly.
        CURLOPT_CUSTOMREQUEST  => $method,  // A custom request method to use instead of "GET" or "HEAD" when doing a HTTP request. This is useful for doing "DELETE" or other, more obscure HTTP requests. Valid values are things like "GET", "POST", "CONNECT" and so on; i.e.
        CURLOPT_HEADER         => true,  // true to include the header in the output.
        CURLOPT_HTTPHEADER     => $header  // An array of HTTP header fields to set, in the format array('Content-type: text/plain', 'Content-length: 100')
    ));
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);  // As of cURL 7.10.8, this is a legacy alias of CURLINFO_RESPONSE_CODE
    $header_size = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
    curl_close($ch);
    // Separate response header from body
    $headers = explode("\n", substr($response, 0, $header_size));
    $body = substr($response, $header_size);
    logRequest($method, $url, $data, $httpCode, $headers);
    if ($body == '') {
        if ($httpCode >= 200 && $httpCode < 300) {
            // No response body, but response code indicates success https://developer.mozilla.org/en-US/docs/Web/HTTP/Status#successful_responses
            return null;
        } else {
            die('Error with response HTTP ' . $httpCode);
        }
    }
    $responseJson = json_decode($body);
    if (json_last_error() == JSON_ERROR_NONE) {
        if ($httpCode >= 400) {
            die('Error: ' . processErrorResponse($responseJson));
        }
        return $responseJson;
    } else {
        // Something bad happened, no JSON in response.
        die('Error: ' . $response . ' (' . $url . ')');
    }
}

/**
 * Get the Uic of an instrument by its ISIN.
 * @param string $isin The ISIN.
 * @param string $assetTypes One or more asset types, separated by comma.
 * @return string
 */
function getUicByIsin($isin, $assetTypes) {
    $instrumentsResponse = getApiResponse('GET', '/ref/v1/instruments?IncludeNonTradable=false&Keywords=' . urlencode($isin) . '&AssetTypes=' . urlencode($assetTypes), null);
    if (count($instrumentsResponse->Data) == 0) {
        die('Instrument not found. Isin: ' . $isin);
    }
    $instrument = $instrumentsResponse->Data[0];
    if ($instrument->SummaryType != 'Instrument') {
        die('Option root found. See https://saxobank.github.io/openapi-samples-js/instruments/instrument-search/ on how to handle option series.');
    }
    return $instrument->Identifier;
}

/**
 * Place the actual order.
 * @param string $uic       The Saxobank id of the instrument.
 * @param string $assetType The instrument type.
 * @return string
 */
function placeOrder($uic, $assetType) {
    global $accountKey;
    // This order object is borrowed from the example at https://saxobank.github.io/openapi-samples-js/orders/stocks/
    $data = array(
        //'AccountKey' => $accountKey,  // By not specifying this, the default account for this AssetType will be used.
        'BuySell' => 'Buy',
        'Amount' => 100,
        'Uic' => $uic,  // Instruments can be found using GET /ref/v1/instruments (https://saxobank.github.io/openapi-samples-js/instruments/instrument-search/)
        'AssetType' => $assetType,
        'OrderType' => 'Market',
        'OrderDuration' => array(
            'DurationType' => 'DayOrder'
        ),
        'ExternalReference' => 'MyPhpOrderCorrelationId',
        'ManualOrder' => true
    );
    // Use the X-Request-ID header is you don't want two of the same orders being blocked.
    $ordersResponse = getApiResponse('POST', '/trade/v2/orders', $data);
    echo "\nOrders response: " . json_encode($ordersResponse, JSON_PRETTY_PRINT) . "\n";
}

if ($accessToken === '') {
    // Only for demonstration purposes:
    die('You must add an access (bearer) token first. Get your 24-hour token here https://www.developer.saxo/openapi/token/current, or create an app and request one.');
}
$uic = getUicByIsin('US5949181045', 'Stock');  // This is the ISIN of Microsoft Corp
// Ideally there is a precheck first, and a check on the order conditions to see in advance if the order can go through..
placeOrder($uic, 'Stock');
