<?php

/**
 * Mail Platform :: front-controller.
 *
 * O Apache encaminha para cá (FallbackResource) tudo o que não é arquivo
 * estático em public/. Rotas:
 *   /api/admin/*    AdminController   (painel, restrito por IP no vhost)
 *   /api/webmail/*  WebmailController (webmail zero-knowledge)
 *   /               redireciona para /webmail.html
 */

declare(strict_types=1);

use MailPlatform\Config\Config;
use MailPlatform\Controllers\AdminController;
use MailPlatform\Controllers\WebmailController;
use MailPlatform\Http\HttpException;
use MailPlatform\Http\Request;
use MailPlatform\Http\Response;
use MailPlatform\Http\Router;
use MailPlatform\Http\Session;

spl_autoload_register(static function (string $class): void {
    $prefix = 'MailPlatform\\';
    if (!str_starts_with($class, $prefix)) {
        return;
    }
    $file = dirname(__DIR__) . '/src/' . str_replace('\\', '/', substr($class, strlen($prefix))) . '.php';
    if (is_file($file)) {
        require $file;
    }
});

ini_set('display_errors', '0');
ini_set('log_errors', '1');

$request = Request::fromGlobals();
$path = $request->path;

// ---------------------------------------------------------------------------
// Fora da API: páginas do frontend
// ---------------------------------------------------------------------------
if (!str_starts_with($path, '/api/')) {
    if ($path === '/' || $path === '/index.php') {
        Response::redirect('/webmail.html')->send();
        return;
    }
    $page = match ($path) {
        '/admin', '/admin/', '/admin.html' => 'admin.html',
        '/webmail', '/webmail/', '/webmail.html' => 'webmail.html',
        default => null,
    };
    if ($page !== null && is_file(__DIR__ . '/' . $page)) {
        Response::redirect('/' . $page)->send();
        return;
    }
    $status = $page !== null ? 503 : 404;
    $title = $page !== null ? 'Interface em implantação' : 'Página não encontrada';
    $text = $page !== null
        ? 'O backend está ativo; a interface web será publicada na próxima atualização.'
        : 'O endereço solicitado não existe.';
    (new Response($status, "<!doctype html>\n<html lang=\"pt-BR\"><head><meta charset=\"utf-8\"><title>Mail Platform</title></head>"
        . "<body><h1>{$title}</h1><p>{$text}</p></body></html>\n", [
            'Content-Type' => 'text/html; charset=utf-8',
            'Cache-Control' => 'no-store',
        ]))->send();
    return;
}

// ---------------------------------------------------------------------------
// API
// ---------------------------------------------------------------------------
try {
    $config = Config::load();
    $secure = $config->get('MP_ENV', 'production') === 'production' || $request->isSecure();
    $session = new Session($secure);

    $router = new Router();
    (new AdminController($config, $session))->register($router);
    (new WebmailController($config, $session))->register($router);

    $response = $router->dispatch($request);
} catch (HttpException $e) {
    $response = Response::error($e);
} catch (\PDOException | \RuntimeException $e) {
    if (!$e instanceof \PDOException && $e->getCode() !== 503) {
        error_log(sprintf('mail-platform: %s: %s em %s:%d', $e::class, $e->getMessage(), $e->getFile(), $e->getLine()));
        $response = Response::json(['error' => 'internal_error', 'message' => 'Erro interno'], 500);
        $response->send();
        return;
    }
    error_log('mail-platform: banco de dados: ' . $e->getMessage());
    $response = Response::json(['error' => 'database_unavailable', 'message' => 'Banco de dados indisponível'], 503)
        ->withHeader('Retry-After', '30');
} catch (\Throwable $e) {
    error_log(sprintf('mail-platform: %s: %s em %s:%d', $e::class, $e->getMessage(), $e->getFile(), $e->getLine()));
    $response = Response::json(['error' => 'internal_error', 'message' => 'Erro interno'], 500);
}

if (!headers_sent()) {
    header_remove('X-Powered-By');
}
$response->send();
