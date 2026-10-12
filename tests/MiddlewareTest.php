<?php

declare(strict_types=1);

namespace EchoFusion\AuthManager\Tests;

use EchoFusion\AuthManager\AuthManager;
use EchoFusion\AuthManager\Hashing\PasswordHasher;
use EchoFusion\AuthManager\Middleware\AuthenticateMiddleware;
use EchoFusion\AuthManager\Middleware\GuestMiddleware;
use EchoFusion\Contracts\AuthManager\UserInterface;
use EchoFusion\SessionManager\ArraySession;
use GuzzleHttp\Psr7\HttpFactory;
use GuzzleHttp\Psr7\Response;
use GuzzleHttp\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use function json_decode;

final class MiddlewareTest extends TestCase
{
    private AuthManager $auth;

    private ArraySession $session;

    protected function setUp(): void
    {
        $hash = (new PasswordHasher('bcrypt', ['cost' => 4]))->hash('secret');
        $this->session = new ArraySession();
        $container = new TestContainer();
        $container->set(\EchoFusion\Contracts\SessionManager\SessionInterface::class, fn () => $this->session);

        $this->auth = new AuthManager($container, [
            'default' => 'web',
            'guards' => [
                'web' => ['driver' => 'session', 'provider' => 'users'],
                'api' => ['driver' => 'token', 'provider' => 'users'],
            ],
            'providers' => ['users' => ['driver' => 'array', 'users' => [['id' => 1, 'email' => 'ann@example.com', 'password' => $hash, 'token' => 'tok-1']]]],
        ]);
    }

    /**
     * @return RequestHandlerInterface&object{request: ?ServerRequestInterface}
     */
    private function handler(): RequestHandlerInterface
    {
        return new class() implements RequestHandlerInterface {
            public ?ServerRequestInterface $request = null;

            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                $this->request = $request;

                return new Response(200, [], 'ok');
            }
        };
    }

    public function testAuthenticatedRequestsPassWithTheUserAttached(): void
    {
        $this->auth->statefulGuard('web')->attempt(['email' => 'ann@example.com', 'password' => 'secret']);
        $handler = $this->handler();

        $response = (new AuthenticateMiddleware($this->auth, new HttpFactory()))->process(new ServerRequest('GET', '/'), $handler);

        $this->assertSame(200, $response->getStatusCode());
        $this->assertInstanceOf(UserInterface::class, $handler->request?->getAttribute('auth.user'));
        $this->assertSame('web', $handler->request?->getAttribute('auth.guard'));
    }

    public function testBrowsersAreRedirectedWhenNotAuthenticated(): void
    {
        $handler = $this->handler();

        $response = (new AuthenticateMiddleware($this->auth, new HttpFactory(), null, '/login'))->process(new ServerRequest('GET', '/'), $handler);

        $this->assertSame(302, $response->getStatusCode());
        $this->assertSame('/login', $response->getHeaderLine('Location'));
        $this->assertNull($handler->request);
    }

    public function testApiClientsGetA401Json(): void
    {
        $withRedirect = new AuthenticateMiddleware($this->auth, new HttpFactory(), null, '/login');

        foreach ([['Accept', 'application/json'], ['X-Requested-With', 'XMLHttpRequest']] as [$header, $value]) {
            $response = $withRedirect->process((new ServerRequest('GET', '/'))->withHeader($header, $value), $this->handler());

            $this->assertSame(401, $response->getStatusCode());
            $this->assertSame('application/json', $response->getHeaderLine('Content-Type'));
            $this->assertSame(['message' => 'Unauthenticated.'], json_decode((string) $response->getBody(), true));
        }

        $noRedirect = (new AuthenticateMiddleware($this->auth, new HttpFactory()))->process(new ServerRequest('GET', '/'), $this->handler());
        $this->assertSame(401, $noRedirect->getStatusCode(), 'without a redirect configured it is always a 401');
    }

    public function testTheTokenGuardGetsTheRequest(): void
    {
        $middleware = new AuthenticateMiddleware($this->auth, new HttpFactory(), 'api');
        $handler = $this->handler();

        $ok = $middleware->process((new ServerRequest('GET', '/'))->withHeader('Authorization', 'Bearer tok-1'), $handler);
        $this->assertSame(200, $ok->getStatusCode());
        $this->assertSame('api', $handler->request?->getAttribute('auth.guard'));

        $denied = $middleware->process((new ServerRequest('GET', '/'))->withHeader('Authorization', 'Bearer wrong'), $this->handler());
        $this->assertSame(401, $denied->getStatusCode());

        // a second request on the same guard must not keep the first user
        $again = $middleware->process(new ServerRequest('GET', '/'), $this->handler());
        $this->assertSame(401, $again->getStatusCode());
    }

    public function testGuestMiddleware(): void
    {
        $middleware = new GuestMiddleware($this->auth, new HttpFactory(), null, '/home');

        $handler = $this->handler();
        $this->assertSame(200, $middleware->process(new ServerRequest('GET', '/login'), $handler)->getStatusCode());
        $this->assertNotNull($handler->request);

        $this->auth->statefulGuard('web')->attempt(['email' => 'ann@example.com', 'password' => 'secret']);

        $redirect = $middleware->process(new ServerRequest('GET', '/login'), $this->handler());
        $this->assertSame(302, $redirect->getStatusCode());
        $this->assertSame('/home', $redirect->getHeaderLine('Location'));

        $json = $middleware->process((new ServerRequest('GET', '/login'))->withHeader('Accept', 'application/json'), $this->handler());
        $this->assertSame(403, $json->getStatusCode());
        $this->assertSame(['message' => 'Already authenticated.'], json_decode((string) $json->getBody(), true));
    }

    public function testGuestMiddlewareWithTheTokenGuard(): void
    {
        $middleware = new GuestMiddleware($this->auth, new HttpFactory(), 'api', null);

        $this->assertSame(200, $middleware->process(new ServerRequest('POST', '/register'), $this->handler())->getStatusCode());
        $this->assertSame(403, $middleware->process((new ServerRequest('POST', '/register'))->withHeader('Authorization', 'Bearer tok-1'), $this->handler())->getStatusCode());
    }
}
