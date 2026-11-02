<?php
/**
 * VPSProxy-like gate (multi-hop capable).
 *
 * One PHP file you upload to a web host. It accepts an AES-256-GCM encrypted
 * request from the client (or from a previous gate in the chain), peels one
 * encryption layer, and either:
 *   - forwards the inner payload to the NEXT gate ("forward" layer), or
 *   - performs the real HTTP request to the target and returns the encrypted
 *     response ("target" layer / exit node).
 *
 * Intermediate gates can read only {next, payload} — never the final target.
 * The exit gate can read the target but not the original client. That split is
 * the whole point of the chain.
 *
 * ---- CONFIGURE PER GATE ----
 * Each gate has its OWN password + key. Generate a key with:  openssl rand -hex 32
 */
const GATE_PASSWORD = 'change-me-per-gate';
const GATE_KEY_HEX  = '0000000000000000000000000000000000000000000000000000000000000000'; // 64 hex chars = 32 bytes

// -------------------- crypto --------------------

function key_bytes(): string {
    $k = hex2bin(GATE_KEY_HEX);
    if ($k === false || strlen($k) !== 32) {
        fail('gate misconfigured: key must be 64 hex chars');
    }
    return $k;
}

/** wire format: base64( nonce(12) || ciphertext || tag(16) ) */
function gate_encrypt(string $plain, string $key): string {
    $nonce = random_bytes(12);
    $tag = '';
    $ct = openssl_encrypt($plain, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $nonce, $tag);
    if ($ct === false) fail('encrypt failed');
    return base64_encode($nonce . $ct . $tag);
}

function gate_decrypt(string $b64, string $key): string {
    $raw = base64_decode($b64, true);
    if ($raw === false || strlen($raw) < 12 + 16) fail('bad ciphertext envelope');
    $nonce = substr($raw, 0, 12);
    $rest  = substr($raw, 12);
    $tag   = substr($rest, -16);
    $ct    = substr($rest, 0, -16);
    $plain = openssl_decrypt($ct, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $nonce, $tag);
    if ($plain === false) fail('decrypt/auth failed (wrong key, password, or corrupted data)');
    return $plain;
}

/** error channel: non-200 + plaintext so the client can name the failing link */
function fail(string $msg): void {
    http_response_code(502);
    header('Content-Type: text/plain');
    echo 'GATE-ERROR: ' . $msg;
    exit;
}

// -------------------- main --------------------

$key = key_bytes();

$body = file_get_contents('php://input');
if ($body === false || $body === '') fail('empty request body');

$plain = gate_decrypt(trim($body), $key);
$obj = json_decode($plain, true);
if (!is_array($obj)) fail('inner payload is not JSON');

if (($obj['pw'] ?? null) !== GATE_PASSWORD) fail('bad password for this gate');

$type = $obj['type'] ?? '';

if ($type === 'forward') {
    // intermediate hop: relay the next layer to the next gate, pass response back opaque
    $next = $obj['next'] ?? '';
    $payload = $obj['payload'] ?? '';
    if ($next === '' || $payload === '') fail('forward layer missing next/payload');

    $resp = relay($next, $payload);
    header('Content-Type: application/octet-stream');
    echo $resp;
    exit;
}

if ($type === 'target') {
    // exit node: perform the real request, return ENCRYPTED response (only client can read it)
    $out = do_target_request($obj);
    header('Content-Type: application/octet-stream');
    echo gate_encrypt(json_encode($out), $key);
    exit;
}

fail('unknown layer type: ' . $type);

// -------------------- helpers --------------------

/** POST an opaque payload to the next gate, return its raw response body */
function relay(string $url, string $payload): string {
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => $payload,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => 60,
        CURLOPT_HTTPHEADER     => ['Content-Type: application/octet-stream'],
    ]);
    $resp = curl_exec($ch);
    if ($resp === false) fail('relay to next gate failed: ' . curl_error($ch));
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    if ($code !== 200) {
        // next gate already returned a GATE-ERROR plaintext; bubble it up
        fail('downstream gate returned HTTP ' . $code . ': ' . substr($resp, 0, 300));
    }
    return $resp;
}

/** perform the actual target request described in the decrypted target layer */
function do_target_request(array $obj): array {
    $method  = strtoupper($obj['method'] ?? 'GET');
    $url     = $obj['url'] ?? '';
    $headers = $obj['headers'] ?? [];      // [[name, value], ...]
    $bodyB64 = $obj['body'] ?? '';
    if ($url === '') fail('target layer missing url');

    $reqHeaders = [];
    foreach ($headers as $h) {
        if (is_array($h) && count($h) === 2) $reqHeaders[] = $h[0] . ': ' . $h[1];
    }

    $respHeaders = [];
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_CUSTOMREQUEST  => $method,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HEADER         => false,
        CURLOPT_FOLLOWLOCATION => false,   // let the browser follow redirects itself
        CURLOPT_TIMEOUT        => 60,
        CURLOPT_HTTPHEADER     => $reqHeaders,
        CURLOPT_HEADERFUNCTION => function ($ch, $line) use (&$respHeaders) {
            $p = explode(':', $line, 2);
            if (count($p) === 2) $respHeaders[] = [trim($p[0]), trim($p[1])];
            return strlen($line);
        },
    ]);
    if ($method === 'POST' || $method === 'PUT' || $method === 'PATCH') {
        $raw = base64_decode($bodyB64, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $raw === false ? '' : $raw);
    }

    $respBody = curl_exec($ch);
    if ($respBody === false) {
        $err = curl_error($ch);
        curl_close($ch);
        return ['status' => 502, 'headers' => [['Content-Type', 'text/plain']],
                'body' => base64_encode('curl error: ' . $err)];
    }
    $status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    return [
        'status'  => $status,
        'headers' => $respHeaders,
        'body'    => base64_encode($respBody),
    ];
}
