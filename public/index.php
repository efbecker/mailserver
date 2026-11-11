<?php
// Mail Platform :: front-controller provisório.
// Substituído pelo roteador completo na Entrega 3. Até lá, responde 503 para
// que o Apache tenha um DocumentRoot válido e o deploy possa ser verificado.
declare(strict_types=1);

$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';
http_response_code(503);
header('Retry-After: 3600');

if (str_starts_with($path, '/api/')) {
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(['error' => 'service_unavailable', 'message' => 'Backend em implantação'], JSON_UNESCAPED_UNICODE);
    exit;
}

header('Content-Type: text/html; charset=utf-8');
echo "<!doctype html>\n<html lang=\"pt-BR\"><head><meta charset=\"utf-8\"><title>Mail Platform</title></head>"
   . "<body><h1>Mail Platform</h1><p>Infraestrutura instalada. Painel e Webmail em implantação.</p></body></html>\n";
