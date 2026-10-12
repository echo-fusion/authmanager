<?php

declare(strict_types=1);

namespace EchoFusion\AuthManager\Tests;

use EchoFusion\AuthManager\Guards\RequestAwareGuardInterface;
use EchoFusion\AuthManager\Guards\SessionGuard;
use EchoFusion\AuthManager\Guards\TokenGuard;
use EchoFusion\AuthManager\Hashing\PasswordHasher;
use EchoFusion\AuthManager\Users\ArrayUserProvider;
use EchoFusion\AuthManager\Users\GenericUser;
use EchoFusion\Contracts\AuthManager\StatefulGuardInterface;
use EchoFusion\SessionManager\ArraySession;
use GuzzleHttp\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;

final class GuardsTest extends TestCase
{
    private ArraySession $session;

    private ArrayUserProvider $provider;

    protected function setUp(): void
    {
        $hasher = new PasswordHasher('bcrypt', ['cost' => 4]);
        $this->session = new ArraySession();
        $this->provider = new ArrayUserProvider($hasher, [
            ['id' => 1, 'email' => 'ann@example.com', 'password' => $hasher->hash('secret'), 'token' => 'tok-1'],
        ]);
    }

    public function testSessionGuardLifecycle(): void
    {
        $guard = new SessionGuard($this->session, $this->provider);

        $this->assertInstanceOf(StatefulGuardInterface::class, $guard);
        $this->assertTrue($guard->guest());
        $this->assertFalse($guard->check());
        $this->assertNull($guard->id());
        $this->assertTrue($this->session->isActive(), 'the guard starts the session when it needs it');

        $this->assertFalse($guard->attempt(['email' => 'ann@example.com', 'password' => 'wrong']));
        $this->assertFalse($guard->attempt(['email' => 'nobody@example.com', 'password' => 'secret']));
        $this->assertTrue($guard->guest());

        $this->assertTrue($guard->attempt(['email' => 'ann@example.com', 'password' => 'secret']));
        $this->assertTrue($guard->check());
        $this->assertSame(1, $guard->id());
        $this->assertSame(1, $this->session->get('auth_user'));
        $this->assertSame(1, $guard->user()?->getAuthIdentifier());

        $guard->logout();
        $this->assertTrue($guard->guest());
        $this->assertFalse($this->session->has('auth_user'));
    }

    public function testTheUserIsRestoredFromTheSessionOnTheNextRequest(): void
    {
        $this->session->start();
        $this->session->put('auth_user', 1);

        $guard = new SessionGuard($this->session, $this->provider);

        $this->assertSame(1, $guard->id());
    }

    public function testAStaleSessionIdIsForgotten(): void
    {
        $this->session->start();
        $this->session->put('auth_user', 999);

        $guard = new SessionGuard($this->session, $this->provider);

        $this->assertTrue($guard->guest());
        $this->assertFalse($this->session->has('auth_user'));
    }

    public function testLoginAndLogoutRegenerateTheSessionId(): void
    {
        $spy = new class() implements \EchoFusion\Contracts\SessionManager\SessionInterface {
            public int $regenerated = 0;

            /**
             * @var array<string, mixed>
             */
            private array $data = [];

            private bool $active = false;

            public function start(): void
            {
                $this->active = true;
            }

            public function save(): void
            {
            }

            public function isActive(): bool
            {
                return $this->active;
            }

            public function get(string $key, mixed $default = null): mixed
            {
                return $this->data[$key] ?? $default;
            }

            public function put(string $key, mixed $value): void
            {
                $this->data[$key] = $value;
            }

            public function has(string $key): bool
            {
                return isset($this->data[$key]);
            }

            public function forget(string $key): void
            {
                unset($this->data[$key]);
            }

            public function regenerate(): bool
            {
                $this->regenerated++;

                return true;
            }

            public function flash(string $key, array $messages): void
            {
            }

            public function getFlash(string $key): array
            {
                return [];
            }
        };

        $guard = new SessionGuard($spy, $this->provider);
        $guard->login(new GenericUser(1));
        $this->assertSame(1, $spy->regenerated, 'login prevents session fixation');

        $guard->logout();
        $this->assertSame(2, $spy->regenerated);
    }

    public function testValidateDoesNotLogIn(): void
    {
        $guard = new SessionGuard($this->session, $this->provider);

        $this->assertTrue($guard->validate(['email' => 'ann@example.com', 'password' => 'secret']));
        $this->assertFalse($guard->validate(['email' => 'ann@example.com', 'password' => 'nope']));
        $this->assertFalse($guard->validate(['email' => 'nobody@example.com', 'password' => 'secret']));
        $this->assertTrue($guard->guest());
    }

    public function testCustomSessionKeyAndAlreadyActiveSession(): void
    {
        $this->session->start();
        $guard = new SessionGuard($this->session, $this->provider, 'uid');
        $guard->login(new GenericUser(1));

        $this->assertSame(1, $this->session->get('uid'));
    }

    private function request(): ServerRequest
    {
        return new ServerRequest('GET', '/api');
    }

    public function testTokenGuardReadsTheBearerHeader(): void
    {
        $guard = new TokenGuard($this->provider);

        $this->assertInstanceOf(RequestAwareGuardInterface::class, $guard);
        $this->assertTrue($guard->guest(), 'without a request there is no token');

        $guard->setRequest($this->request()->withHeader('Authorization', 'Bearer tok-1'));
        $this->assertSame('tok-1', $guard->token());
        $this->assertTrue($guard->check());
        $this->assertSame(1, $guard->id());
        $this->assertFalse($guard->guest());
    }

    public function testBearerSchemeIsCaseInsensitiveAndMustMatch(): void
    {
        $guard = new TokenGuard($this->provider);

        $guard->setRequest($this->request()->withHeader('Authorization', 'bearer tok-1'));
        $this->assertSame('tok-1', $guard->token());

        $guard->setRequest($this->request()->withHeader('Authorization', 'Basic dXNlcjpwYXNz'));
        $this->assertNull($guard->token());
        $this->assertTrue($guard->guest());

        $guard->setRequest($this->request()->withHeader('Authorization', 'Bearer'));
        $this->assertNull($guard->token());
    }

    public function testWrongTokenIsAGuest(): void
    {
        $guard = new TokenGuard($this->provider);
        $guard->setRequest($this->request()->withHeader('Authorization', 'Bearer nope'));

        $this->assertTrue($guard->guest());
    }

    public function testBareHeaderQueryAndBodyTokens(): void
    {
        $bare = new TokenGuard($this->provider, 'X-Api-Key', null);
        $bare->setRequest($this->request()->withHeader('X-Api-Key', 'tok-1'));
        $this->assertSame(1, $bare->id());

        $query = new TokenGuard($this->provider, 'Authorization', 'Bearer', 'api_token');
        $query->setRequest($this->request()->withQueryParams(['api_token' => 'tok-1']));
        $this->assertSame(1, $query->id());

        $body = new TokenGuard($this->provider, 'Authorization', 'Bearer', null, 'token');
        $body->setRequest($this->request()->withParsedBody(['token' => 'tok-1']));
        $this->assertSame(1, $body->id());
        $body->setRequest($this->request()->withParsedBody('not-an-array'));
        $this->assertNull($body->token());

        $disabled = new TokenGuard($this->provider);
        $disabled->setRequest($this->request()->withQueryParams(['api_token' => 'tok-1']));
        $this->assertTrue($disabled->guest(), 'query tokens are off unless configured');
    }

    public function testSettingANewRequestResetsTheUser(): void
    {
        $guard = new TokenGuard($this->provider);
        $guard->setRequest($this->request()->withHeader('Authorization', 'Bearer tok-1'));
        $this->assertTrue($guard->check());

        $guard->setRequest($this->request());
        $this->assertTrue($guard->guest());
    }

    public function testTokenGuardValidate(): void
    {
        $guard = new TokenGuard($this->provider);

        $this->assertTrue($guard->validate(['token' => 'tok-1']));
        $this->assertFalse($guard->validate(['token' => 'nope']));
        $this->assertFalse($guard->validate(['token' => '']));
        $this->assertFalse($guard->validate([]));
    }
}
