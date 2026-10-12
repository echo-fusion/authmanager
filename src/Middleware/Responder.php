<?php

declare(strict_types=1);

namespace EchoFusion\AuthManager\Middleware;

use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use const JSON_THROW_ON_ERROR;
use function json_encode;
use function str_contains;
use function strtolower;

/**
 * Builds the "not allowed" response: a redirect for browsers, a JSON error for APIs.
 *
 * @internal
 */
final class Responder
{
    public function __construct(private readonly ResponseFactoryInterface $responses)
    {
    }

    public function deny(ServerRequestInterface $request, int $status, string $message, ?string $redirectTo): ResponseInterface
    {
        if ($redirectTo !== null && !self::wantsJson($request)) {
            return $this->responses->createResponse(302)->withHeader('Location', $redirectTo);
        }

        $response = $this->responses->createResponse($status)->withHeader('Content-Type', 'application/json');
        $response->getBody()->write(json_encode(['message' => $message], JSON_THROW_ON_ERROR));

        return $response;
    }

    private static function wantsJson(ServerRequestInterface $request): bool
    {
        return str_contains(strtolower($request->getHeaderLine('Accept')), 'json')
            || strtolower($request->getHeaderLine('X-Requested-With')) === 'xmlhttprequest';
    }
}
