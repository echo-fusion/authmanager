<?php

declare(strict_types=1);

namespace EchoFusion\AuthManager\Providers;

use EchoFusion\AuthManager\AuthManager;
use EchoFusion\AuthManager\Middleware\AuthenticateMiddleware;
use EchoFusion\AuthManager\Middleware\GuestMiddleware;
use EchoFusion\Contracts\AuthManager\AuthManagerInterface;
use EchoFusion\Contracts\AuthManager\GuardInterface;
use EchoFusion\Contracts\AuthManager\PasswordHasherInterface;
use EchoFusion\Contracts\ServiceManager\SettableContainerInterface;
use EchoFusion\Contracts\ServiceProvider\ServiceProviderInterface;
use LogicException;
use Psr\Http\Message\ResponseFactoryInterface;
use function is_array;
use function is_string;
use function sprintf;

/**
 * Registers the auth services. The container must also provide a PSR-17 `ResponseFactoryInterface`
 * (for the middleware), a `SessionInterface` (for session guards) and a `ConnectionInterface` or
 * `DatabaseManagerInterface` (for the database user provider), whichever your configuration uses.
 *
 * Besides the guards and providers, the `auth` configuration may contain
 * `'middleware' => ['authenticate' => ['guard' => 'web', 'redirect_to' => '/login'], 'guest' => ['guard' => 'web', 'redirect_to' => '/']]`.
 */
class AuthManagerProvider implements ServiceProviderInterface
{
    /**
     * @var array<string, mixed>
     */
    private array $middleware = [];

    public function register(SettableContainerInterface $container): void
    {
        $manager = new AuthManager($container);

        $container->set(AuthManagerInterface::class, static fn (): AuthManager => $manager);
        $container->set(GuardInterface::class, static fn (): GuardInterface => $manager->guard());
        $container->set(PasswordHasherInterface::class, static fn (): PasswordHasherInterface => $manager->hasher());

        $container->set(AuthenticateMiddleware::class, function () use ($container, $manager): AuthenticateMiddleware {
            return new AuthenticateMiddleware(
                $manager,
                $this->responses($container),
                $this->option('authenticate', 'guard'),
                $this->option('authenticate', 'redirect_to'),
            );
        });

        $container->set(GuestMiddleware::class, function () use ($container, $manager): GuestMiddleware {
            return new GuestMiddleware(
                $manager,
                $this->responses($container),
                $this->option('guest', 'guard'),
                $this->option('guest', 'redirect_to') ?? '/',
            );
        });
    }

    /**
     * @param array<string, mixed> $config the "auth" section of the application configuration
     */
    public function boot(SettableContainerInterface $container, array $config = []): void
    {
        $manager = $container->get(AuthManagerInterface::class);
        if (!$manager instanceof AuthManager) {
            throw new LogicException(sprintf('%s must be an %s to be configured.', AuthManagerInterface::class, AuthManager::class));
        }

        $manager->configure($config);
        $this->middleware = is_array($config['middleware'] ?? null) ? $config['middleware'] : [];
    }

    private function responses(SettableContainerInterface $container): ResponseFactoryInterface
    {
        $factory = $container->get(ResponseFactoryInterface::class);
        if (!$factory instanceof ResponseFactoryInterface) {
            throw new LogicException(sprintf('The container entry %s must be a PSR-17 response factory.', ResponseFactoryInterface::class));
        }

        return $factory;
    }

    private function option(string $middleware, string $key): ?string
    {
        $settings = $this->middleware[$middleware] ?? null;
        $value = is_array($settings) ? ($settings[$key] ?? null) : null;

        return is_string($value) ? $value : null;
    }
}
