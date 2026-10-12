<?php

declare(strict_types=1);

namespace EchoFusion\AuthManager\Middleware;

use EchoFusion\AuthManager\Guards\RequestAwareGuardInterface;
use EchoFusion\Contracts\AuthManager\AuthManagerInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * The opposite of {@see AuthenticateMiddleware}: for pages like "login" that logged-in users should not see.
 * Logged-in browsers are redirected to `$redirectTo`; API clients receive a 403 JSON response.
 */
final class GuestMiddleware implements MiddlewareInterface
{
    private readonly Responder $responder;

    public function __construct(
        private readonly AuthManagerInterface $auth,
        ResponseFactoryInterface $responses,
        private readonly ?string $guardName = null,
        private readonly ?string $redirectTo = '/',
    ) {
        $this->responder = new Responder($responses);
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $guard = $this->auth->guard($this->guardName ?? $this->auth->getDefaultGuardName());

        if ($guard instanceof RequestAwareGuardInterface) {
            $guard->setRequest($request);
        }

        if ($guard->check()) {
            return $this->responder->deny($request, 403, 'Already authenticated.', $this->redirectTo);
        }

        return $handler->handle($request);
    }
}
