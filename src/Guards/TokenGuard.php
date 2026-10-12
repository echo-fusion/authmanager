<?php

declare(strict_types=1);

namespace EchoFusion\AuthManager\Guards;

use EchoFusion\Contracts\AuthManager\GuardInterface;
use EchoFusion\Contracts\AuthManager\UserInterface;
use EchoFusion\Contracts\AuthManager\UserProviderInterface;
use Psr\Http\Message\ServerRequestInterface;
use function is_array;
use function is_string;
use function preg_match;
use function preg_quote;
use function sprintf;
use function trim;

/**
 * Stateless guard: the user is whoever owns the token sent with the request. Nothing is stored between requests.
 *
 * The token is read from, in order: the `Authorization: Bearer <token>` header (the header and scheme
 * are configurable), an optional query-string parameter, and an optional form-body field.
 */
final class TokenGuard implements GuardInterface, RequestAwareGuardInterface
{
    private ?ServerRequestInterface $request = null;

    private ?UserInterface $user = null;

    private bool $loaded = false;

    /**
     * @param string $header header that carries the token
     * @param string|null $scheme scheme in front of the token ("Bearer"); null when the header holds the bare token (e.g. X-Api-Key)
     * @param string|null $queryParameter name of a query parameter to read the token from, or null to disable
     * @param string|null $bodyField name of a parsed-body field to read the token from, or null to disable
     */
    public function __construct(
        private readonly UserProviderInterface $provider,
        private readonly string $header = 'Authorization',
        private readonly ?string $scheme = 'Bearer',
        private readonly ?string $queryParameter = null,
        private readonly ?string $bodyField = null,
    ) {
    }

    public function setRequest(ServerRequestInterface $request): void
    {
        $this->request = $request;
        $this->user = null;
        $this->loaded = false;
    }

    public function user(): ?UserInterface
    {
        if ($this->loaded) {
            return $this->user;
        }

        $this->loaded = true;
        $token = $this->token();
        if ($token !== null) {
            $this->user = $this->provider->findByToken($token);
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

    /**
     * @param array<string, mixed> $credentials `['token' => '...']`
     */
    public function validate(array $credentials): bool
    {
        $token = $credentials['token'] ?? null;

        return is_string($token) && $token !== '' && $this->provider->findByToken($token) !== null;
    }

    /**
     * The token of the current request, or null.
     */
    public function token(): ?string
    {
        if ($this->request === null) {
            return null;
        }

        $value = trim($this->request->getHeaderLine($this->header));
        if ($value !== '') {
            if ($this->scheme === null) {
                return $value;
            }

            if (preg_match(sprintf('/^%s\s+(\S+)$/i', preg_quote($this->scheme, '/')), $value, $m) === 1) {
                return $m[1];
            }
        }

        if ($this->queryParameter !== null) {
            $query = $this->request->getQueryParams()[$this->queryParameter] ?? null;
            if (is_string($query) && $query !== '') {
                return $query;
            }
        }

        if ($this->bodyField !== null) {
            $body = $this->request->getParsedBody();
            $field = is_array($body) ? ($body[$this->bodyField] ?? null) : null;
            if (is_string($field) && $field !== '') {
                return $field;
            }
        }

        return null;
    }
}
