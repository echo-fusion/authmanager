<?php

declare(strict_types=1);

namespace EchoFusion\AuthManager\Guards;

use Psr\Http\Message\ServerRequestInterface;

/**
 * A guard that needs the current request (e.g. to read a token from a header).
 * The authentication middleware hands it the request before asking for the user.
 */
interface RequestAwareGuardInterface
{
    public function setRequest(ServerRequestInterface $request): void;
}
