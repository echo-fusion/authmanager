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
 * Lets the request through only when the guard knows the user.
 *
 * On success the request gets the attributes `auth.user` (the UserInterface) and `auth.guard` (the guard name).
 * Otherwise: browsers are redirected to `$redirectTo` (when set), API clients (Accept: JSON, or no redirect
 * configured) receive a 401 JSON response.
 */
final class AuthenticateMiddleware implements MiddlewareInterface
{
    private readonly Responder $responder;

    public function __construct(
        private readonly AuthManagerInterface $auth,
        ResponseFactoryInterface $responses,
        private readonly ?string $guardName = null,
        private readonly ?string $redirectTo = null,
    ) {
        $this->responder = new Responder($responses);
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $name = $this->guardName ?? $this->auth->getDefaultGuardName();
        $guard = $this->auth->guard($name);

        if ($guard instanceof RequestAwareGuardInterface) {
            $guard->setRequest($request);
        }

        $user = $guard->user();
        if ($user === null) {
            return $this->responder->deny($request, 401, 'Unauthenticated.', $this->redirectTo);
        }

        return $handler->handle($request->withAttribute('auth.user', $user)->withAttribute('auth.guard', $name));
    }
}
