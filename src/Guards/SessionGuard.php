<?php

declare(strict_types=1);

namespace EchoFusion\AuthManager\Guards;

use EchoFusion\Contracts\AuthManager\StatefulGuardInterface;
use EchoFusion\Contracts\AuthManager\UserInterface;
use EchoFusion\Contracts\AuthManager\UserProviderInterface;
use EchoFusion\Contracts\SessionManager\SessionInterface;
use function is_int;
use function is_string;

/**
 * Keeps the user id in the session. The session is started when it is first needed.
 *
 * The session id is regenerated on login and logout to prevent session fixation.
 */
final class SessionGuard implements StatefulGuardInterface
{
    private ?UserInterface $user = null;

    private bool $loaded = false;

    public function __construct(
        private readonly SessionInterface $session,
        private readonly UserProviderInterface $provider,
        private readonly string $sessionKey = 'auth_user',
    ) {
    }

    public function user(): ?UserInterface
    {
        if ($this->loaded) {
            return $this->user;
        }

        $this->loaded = true;
        $this->start();

        $id = $this->session->get($this->sessionKey);
        if (is_string($id) || is_int($id)) {
            $this->user = $this->provider->findById($id);
            if ($this->user === null) {
                // the user no longer exists: forget the stale id
                $this->session->forget($this->sessionKey);
            }
        }

        return $this->user;
    }

    public function check(): bool
    {
        return $this->user() !== null;
    }

    public function guest(): bool
    {
        return !$this->check();
    }

    public function id(): string|int|null
    {
        return $this->user()?->getAuthIdentifier();
    }

    public function validate(array $credentials): bool
    {
        $user = $this->provider->findByCredentials($credentials);

        return $user !== null && $this->provider->validateCredentials($user, $credentials);
    }

    public function attempt(array $credentials): bool
    {
        $user = $this->provider->findByCredentials($credentials);
        if ($user === null || !$this->provider->validateCredentials($user, $credentials)) {
            return false;
        }

        $this->login($user);

        return true;
    }

    public function login(UserInterface $user): void
    {
        $this->start();
        $this->session->regenerate();
        $this->session->put($this->sessionKey, $user->getAuthIdentifier());

        $this->user = $user;
        $this->loaded = true;
    }

    public function logout(): void
    {
        $this->start();
        $this->session->forget($this->sessionKey);
        $this->session->regenerate();

        $this->user = null;
        $this->loaded = true;
    }

    private function start(): void
    {
        if (!$this->session->isActive()) {
            $this->session->start();
        }
    }
}
