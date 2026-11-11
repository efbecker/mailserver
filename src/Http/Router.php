<?php

declare(strict_types=1);

namespace MailPlatform\Http;

/**
 * Roteador enxuto: "METHOD /caminho/{param}" -> callable(Request): Response.
 * Parâmetros aceitam apenas [A-Za-z0-9_-] (ids numéricos e UUIDs).
 */
final class Router
{
    /** @var list<array{0:string,1:string,2:callable,3:list<string>}> */
    private array $routes = [];

    public function add(string $method, string $pattern, callable $handler): void
    {
        $names = [];
        $regex = preg_replace_callback('/\{([a-z_]+)\}/', static function (array $m) use (&$names): string {
            $names[] = $m[1];
            return '([A-Za-z0-9_-]{1,64})';
        }, $pattern);
        $this->routes[] = [strtoupper($method), '#^' . $regex . '$#', $handler, $names];
    }

    public function dispatch(Request $request): Response
    {
        $allowed = [];
        foreach ($this->routes as [$method, $regex, $handler, $names]) {
            if (!preg_match($regex, $request->path, $m)) {
                continue;
            }
            if ($method !== $request->method && !($method === 'GET' && $request->method === 'HEAD')) {
                $allowed[] = $method;
                continue;
            }
            $request->params = array_combine($names, array_slice($m, 1)) ?: [];
            return $handler($request);
        }
        if ($allowed !== []) {
            return Response::json(['error' => 'method_not_allowed', 'message' => 'Método não permitido'], 405)
                ->withHeader('Allow', implode(', ', array_unique($allowed)));
        }
        throw HttpException::notFound('Rota não encontrada');
    }
}
