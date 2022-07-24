<?php
header("Content-Type: text/plain");

$bearerToken = 'eyJhbGciOiJFUzI1NiIsIng1dCI6IkRFNDc0QUQ1Q0NGRUFFRTlDRThCRDQ3ODlFRTZDOTEyRjVCM0UzOTQifQ.eyJvYWEiOiI3Nzc3MCIsImlzcyI6Im9hIiwiYWlkIjoiMjE0NyIsInVpZCI6IlhJZVYzRXdlUUNPNXBrU2tvOEYzU0E9PSIsImNpZCI6IlhJZVYzRXdlUUNPNXBrU2tvOEYzU0E9PSIsImlzYSI6IkZhbHNlIiwidGlkIjoiNzE3MiIsInNpZCI6IjgxZTcwMGVmYWIwZTRkZjZiZDMxNTE5ZWYwNGQ4OWM1IiwiZGdpIjoiODQiLCJleHAiOiIxNjU4NjMwMzI5Iiwib2FsIjoiMUYiLCJpaWQiOiI3NzcxMjM3OThhNjY0ZTljOGQ0NzcyMmQxNGZjNjY4OCJ9.y03k_6qtw727izEUCDdDGUGTAlSsEOtk7NUttlu_t5FElYXcL0kZ10BULKleEVj-_GrVsmQlDdVbH-7_G8Zcgw';
$openApiBaseUrl = 'https://gateway.saxobank.com/sim/openapi';

function getTokenLifeTime($bearerToken) {
    $tokenArray = explode('.', $bearerToken);
    $header = json_decode(base64_decode($tokenArray[0]));
    $payload = json_decode(base64_decode($tokenArray[1]));
    $signature = json_decode(base64_decode($tokenArray[2]));
    echo 'Token: ' . $bearerToken . PHP_EOL . PHP_EOL;
    echo 'Header: ' . json_encode($header, JSON_PRETTY_PRINT) . PHP_EOL . PHP_EOL;
    echo 'Payload: ' . json_encode($payload, JSON_PRETTY_PRINT) . PHP_EOL . PHP_EOL;
    echo 'UserKey: ' . $payload->uid . PHP_EOL;
    echo 'ClientKey: ' . $payload->cid . PHP_EOL;
    $expirationDateTime = new DateTime("@$payload->exp", new DateTimeZone('UTC'));
    $now = new DateTime(null, new DateTimeZone('UTC'));
    echo 'Expiration Time (UTC): ' . $expirationDateTime->format('Y-m-d H:i:s') . ' (' . $expirationDateTime->getTimestamp() - $now->getTimestamp() . ' seconds remaining)' . PHP_EOL;
}

getTokenLifeTime($bearerToken);
