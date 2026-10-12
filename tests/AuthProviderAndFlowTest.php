<?php

declare(strict_types=1);

namespace EchoFusion\AuthManager\Tests;

use EchoFusion\AuthManager\AuthManager;
use EchoFusion\AuthManager\Middleware\AuthenticateMiddleware;
use EchoFusion\AuthManager\Middleware\GuestMiddleware;
use EchoFusion\AuthManager\Providers\AuthManagerProvider;
use EchoFusion\AuthManager\Users\DatabaseUserProvider;
use EchoFusion\Contracts\AuthManager\AuthManagerInterface;
use EchoFusion\Contracts\AuthManager\GuardInterface;
use EchoFusion\Contracts\AuthManager\PasswordHasherInterface;
use EchoFusion\Contracts\DatabaseManager\ConnectionInterface;
use EchoFusion\Contracts\SessionManager\SessionInterface;
use EchoFusion\DatabaseManager\Connections\PdoConnection;
use EchoFusion\SessionManager\ArraySession;
use GuzzleHttp\Psr7\HttpFactory;
use GuzzleHttp\Psr7\Response;
use GuzzleHttp\Psr7\ServerRequest;
use LogicException;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use RuntimeException;
use stdClass;
use function hash;

/**
 * The whole thing wired the way an application would: provider + container + real SQLite + sessions.
 */
final class AuthProviderAndFlowTest extends TestCase
{
    private TestContainer $container;

    private PdoConnection $db;

    /**
     * @var array<string, mixed>
     */
    private array $config;

    protected function setUp(): void
    {
        $this->db = new PdoConnection(['driver' => 'sqlite']);
        $this->db->execute('CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, email TEXT UNIQUE, password TEXT, api_token TEXT)');

        $session = new ArraySession();
        $this->container = new TestContainer();
        $this->container->set(SessionInterface::class, static fn () => $session);
        $this->container->set(ConnectionInterface::class, fn () => $this->db);
        $this->container->set(ResponseFactoryInterface::class, static fn () => new HttpFactory());

        $this->config = [
            'default' => 'web',
            'guards' => [
                'web' => ['driver' => 'session', 'provider' => 'users'],
                'api' => ['driver' => 'token', 'provider' => 'users', 'query' => 'api_token'],
            ],
            'providers' => ['users' => ['driver' => 'database']],
            'hasher' => ['options' => ['cost' => 4]],
            'middleware' => [
                'authenticate' => ['guard' => 'web', 'redirect_to' => '/login'],
                'guest' => ['guard' => 'web', 'redirect_to' => '/dashboard'],
            ],
        ];

        $provider = new AuthManagerProvider();
        $provider->register($this->container);
        $provider->boot($this->container, $this->config);
    }

    private function ok(): RequestHandlerInterface
    {
        return new class() implements RequestHandlerInterface {
            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                return new Response(200);
            }
        };
    }

    public function testRegistersTheServices(): void
    {
        $manager = $this->container->get(AuthManagerInterface::class);

        $this->assertInstanceOf(AuthManager::class, $manager);
        $this->assertSame($manager->guard(), $this->container->get(GuardInterface::class));
        $this->assertInstanceOf(PasswordHasherInterface::class, $this->container->get(PasswordHasherInterface::class));
        $this->assertInstanceOf(AuthenticateMiddleware::class, $this->container->get(AuthenticateMiddleware::class));
        $this->assertInstanceOf(GuestMiddleware::class, $this->container->get(GuestMiddleware::class));
    }

    public function testRegisterLoginLogoutFlow(): void
    {
        /** @var AuthManager $auth */
        $auth = $this->container->get(AuthManagerInterface::class);
        /** @var DatabaseUserProvider $users */
        $users = $auth->provider('users');
        $web = $auth->statefulGuard('web');

        // register + log in (what the old Auth::register() did)
        $user = $users->create(['name' => 'Ann', 'email' => 'ann@example.com', 'password' => 'hunter22']);
        $web->login($user);
        $this->assertSame(1, $web->id());

        // the page only logged-in users may see
        $protected = $this->container->get(AuthenticateMiddleware::class)->process(new ServerRequest('GET', '/account'), $this->ok());
        $this->assertSame(200, $protected->getStatusCode());

        // and the login page they may not
        $loginPage = $this->container->get(GuestMiddleware::class)->process(new ServerRequest('GET', '/login'), $this->ok());
        $this->assertSame('/dashboard', $loginPage->getHeaderLine('Location'));

        $web->logout();
        $this->assertSame('/login', $this->container->get(AuthenticateMiddleware::class)->process(new ServerRequest('GET', '/account'), $this->ok())->getHeaderLine('Location'));

        // log in again with the credentials
        $this->assertFalse($web->attempt(['email' => 'ann@example.com', 'password' => 'wrong']));
        $this->assertTrue($web->attempt(['email' => 'ann@example.com', 'password' => 'hunter22']));
    }

    public function testApiTokenFlow(): void
    {
        $this->db->execute('INSERT INTO users (name, email, api_token) VALUES (?, ?, ?)', ['Bot', 'bot@example.com', hash('sha256', 'secret-token')]);
        /** @var AuthManager $auth */
        $auth = $this->container->get(AuthManagerInterface::class);
        $middleware = new AuthenticateMiddleware($auth, new HttpFactory(), 'api');

        $this->assertSame(200, $middleware->process((new ServerRequest('GET', '/api'))->withHeader('Authorization', 'Bearer secret-token'), $this->ok())->getStatusCode());
        $this->assertSame(200, $middleware->process((new ServerRequest('GET', '/api'))->withQueryParams(['api_token' => 'secret-token']), $this->ok())->getStatusCode());
        $this->assertSame(401, $middleware->process((new ServerRequest('GET', '/api'))->withHeader('Authorization', 'Bearer ' . hash('sha256', 'secret-token')), $this->ok())->getStatusCode());
    }

    public function testBootRequiresTheBundledManager(): void
    {
        $container = new TestContainer();
        $container->set(AuthManagerInterface::class, static fn () => new class() implements AuthManagerInterface {
            public function guard(?string $name = null): GuardInterface
            {
                throw new RuntimeException('unused');
            }

            public function has(string $name): bool
            {
                return false;
            }

            public function getDefaultGuardName(): string
            {
                return 'x';
            }
        });

        $this->expectException(LogicException::class);
        (new AuthManagerProvider())->boot($container);
    }

    public function testMiddlewareNeedsAResponseFactoryInTheContainer(): void
    {
        $container = new TestContainer();
        $container->set(ResponseFactoryInterface::class, static fn () => new stdClass());
        $provider = new AuthManagerProvider();
        $provider->register($container);

        $this->expectException(LogicException::class);
        $this->expectExceptionMessage('PSR-17 response factory');
        $container->get(AuthenticateMiddleware::class);
    }

    public function testMiddlewareDefaultsWithoutAnyMiddlewareConfig(): void
    {
        $container = new TestContainer();
        $container->set(SessionInterface::class, static fn () => new ArraySession());
        $container->set(ResponseFactoryInterface::class, static fn () => new HttpFactory());
        $provider = new AuthManagerProvider();
        $provider->register($container);
        $provider->boot($container, [
            'guards' => ['web' => ['driver' => 'session', 'provider' => 'p']],
            'providers' => ['p' => ['driver' => 'array', 'users' => []]],
        ]);

        $denied = $container->get(AuthenticateMiddleware::class)->process(new ServerRequest('GET', '/'), $this->ok());
        $this->assertSame(401, $denied->getStatusCode(), 'no redirect configured, so a 401');
        $this->assertSame(200, $container->get(GuestMiddleware::class)->process(new ServerRequest('GET', '/'), $this->ok())->getStatusCode());
    }
}
