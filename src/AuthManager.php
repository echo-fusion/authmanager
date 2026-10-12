<?php

declare(strict_types=1);

namespace EchoFusion\AuthManager;

use EchoFusion\AuthManager\Exceptions\GuardNotFoundException;
use EchoFusion\AuthManager\Exceptions\InvalidConfigException;
use EchoFusion\AuthManager\Guards\SessionGuard;
use EchoFusion\AuthManager\Guards\TokenGuard;
use EchoFusion\AuthManager\Hashing\PasswordHasher;
use EchoFusion\AuthManager\Users\ArrayUserProvider;
use EchoFusion\AuthManager\Users\DatabaseUserProvider;
use EchoFusion\Contracts\AuthManager\AuthManagerInterface;
use EchoFusion\Contracts\AuthManager\GuardInterface;
use EchoFusion\Contracts\AuthManager\PasswordHasherInterface;
use EchoFusion\Contracts\AuthManager\StatefulGuardInterface;
use EchoFusion\Contracts\AuthManager\UserProviderInterface;
use EchoFusion\Contracts\DatabaseManager\ConnectionInterface;
use EchoFusion\Contracts\DatabaseManager\DatabaseManagerInterface;
use EchoFusion\Contracts\SessionManager\SessionInterface;
use Psr\Container\ContainerInterface;
use function array_diff_key;
use function array_key_exists;
use function array_key_first;
use function array_values;
use function implode;
use function in_array;
use function is_a;
use function is_array;
use function is_string;
use function sprintf;

/**
 * Named guards and user providers, chosen by configuration.
 *
 * The manager only knows interfaces. The session, the database connection and the response factory are
 * fetched from a PSR-11 container when a guard needs them, so any implementation can sit behind them.
 *
 * <code>
 * [
 *     'default' => 'web',
 *     'guards' => [
 *         'web' => ['driver' => 'session', 'provider' => 'users', 'key' => 'auth_user'],
 *         'api' => ['driver' => 'token', 'provider' => 'users', 'header' => 'Authorization', 'scheme' => 'Bearer', 'query' => 'api_token'],
 *         'custom' => ['class' => MyGuard::class, 'provider' => 'users'],       // new MyGuard($provider, $definition, $container)
 *     ],
 *     'providers' => [
 *         'users' => ['driver' => 'database', 'connection' => null, 'table' => 'users', 'id' => 'id', 'password' => 'password', 'token' => 'api_token'],
 *         'staff' => ['driver' => 'array', 'users' => [['id' => 1, 'email' => 'a@b.c', 'password' => '<hash>']]],
 *         'ldap'  => ['class' => LdapProvider::class],                           // new LdapProvider($definition, $container)
 *     ],
 *     'hasher' => ['algorithm' => 'bcrypt', 'options' => ['cost' => 12]],
 * ]
 * </code>
 */
final class AuthManager implements AuthManagerInterface
{
    private const GUARD_DRIVERS = ['session', 'token'];

    private const PROVIDER_DRIVERS = ['database', 'array'];

    /**
     * @var array<string, array<string, mixed>>
     */
    private array $guardDefinitions = [];

    /**
     * @var array<string, array<string, mixed>>
     */
    private array $providerDefinitions = [];

    /**
     * @var array<string, mixed>
     */
    private array $hasherDefinition = [];

    private ?string $default = null;

    /**
     * @var array<string, GuardInterface>
     */
    private array $guards = [];

    /**
     * @var array<string, UserProviderInterface>
     */
    private array $providers = [];

    private ?PasswordHasherInterface $hasher = null;

    /**
     * @param array<string, mixed> $config
     *
     * @throws InvalidConfigException
     */
    public function __construct(private readonly ContainerInterface $container, array $config = [])
    {
        $this->configure($config);
    }

    /**
     * Replace the configuration. Guards and providers created so far are dropped.
     *
     * @param array<string, mixed> $config
     *
     * @throws InvalidConfigException
     */
    public function configure(array $config): void
    {
        $guards = $this->definitions($config, 'guards');
        $providers = $this->definitions($config, 'providers');

        $default = $config['default'] ?? array_key_first($guards);
        if ($guards !== [] && (!is_string($default) || !isset($guards[$default]))) {
            throw new InvalidConfigException(sprintf('The default guard "%s" is not defined in "guards".', is_string($default) ? $default : ''));
        }

        $hasher = $config['hasher'] ?? [];
        if (!is_array($hasher)) {
            throw new InvalidConfigException('The "hasher" setting must be an array.');
        }

        $this->guardDefinitions = $guards;
        $this->providerDefinitions = $providers;
        $this->hasherDefinition = $hasher;
        $this->default = $guards === [] ? null : (string) $default;
        $this->guards = $this->providers = [];
        $this->hasher = null;
    }

    public function guard(?string $name = null): GuardInterface
    {
        $name ??= $this->getDefaultGuardName();

        return $this->guards[$name] ??= $this->createGuard($name);
    }

    /**
     * A guard that can log users in and out (such as the session guard).
     *
     * @throws InvalidConfigException when the guard is stateless
     */
    public function statefulGuard(?string $name = null): StatefulGuardInterface
    {
        $guard = $this->guard($name);

        return $guard instanceof StatefulGuardInterface
            ? $guard
            : throw new InvalidConfigException(sprintf('Guard "%s" is stateless and cannot log users in or out.', $name ?? $this->getDefaultGuardName()));
    }

    public function has(string $name): bool
    {
        return isset($this->guardDefinitions[$name]);
    }

    public function getDefaultGuardName(): string
    {
        return $this->default ?? throw new InvalidConfigException('No authentication guards are configured.');
    }

    public function hasher(): PasswordHasherInterface
    {
        if ($this->hasher !== null) {
            return $this->hasher;
        }

        $algorithm = $this->hasherDefinition['algorithm'] ?? 'bcrypt';
        $options = $this->hasherDefinition['options'] ?? [];
        if (!is_string($algorithm) || !is_array($options)) {
            throw new InvalidConfigException('The hasher needs a string "algorithm" and an array of "options".');
        }

        /** @var array<string, int> $options */
        return $this->hasher = new PasswordHasher($algorithm, $options);
    }

    public function provider(string $name): UserProviderInterface
    {
        return $this->providers[$name] ??= $this->createProvider($name);
    }

    private function createGuard(string $name): GuardInterface
    {
        $definition = $this->guardDefinitions[$name] ?? throw new GuardNotFoundException(sprintf('Authentication guard "%s" is not defined.', $name));
        $providerName = $definition['provider'] ?? null;
        if (!is_string($providerName)) {
            throw new InvalidConfigException(sprintf('Guard "%s" needs a "provider".', $name));
        }
        $provider = $this->provider($providerName);

        $class = $definition['class'] ?? null;
        if ($class !== null) {
            if (!is_string($class) || !is_a($class, GuardInterface::class, true)) {
                throw new InvalidConfigException(sprintf('The "class" of guard "%s" must implement %s.', $name, GuardInterface::class));
            }

            return new $class($provider, array_diff_key($definition, ['class' => true]), $this->container);
        }

        $driver = $definition['driver'] ?? null;

        return match ($driver) {
            'session' => $this->sessionGuard($provider, $definition),
            'token' => $this->tokenGuard($provider, $definition),
            default => throw new InvalidConfigException(sprintf(
                'Guard "%s" needs a "driver" (%s) or a "class" implementing %s.',
                $name,
                implode(', ', self::GUARD_DRIVERS),
                GuardInterface::class,
            )),
        };
    }

    /**
     * @param array<string, mixed> $definition
     */
    private function sessionGuard(UserProviderInterface $provider, array $definition): SessionGuard
    {
        $session = $this->container->get(SessionInterface::class);
        if (!$session instanceof SessionInterface) {
            throw new InvalidConfigException(sprintf('The container entry %s must be a session.', SessionInterface::class));
        }

        $key = $definition['key'] ?? 'auth_user';

        return new SessionGuard($session, $provider, is_string($key) ? $key : 'auth_user');
    }

    /**
     * @param array<string, mixed> $definition
     */
    private function tokenGuard(UserProviderInterface $provider, array $definition): TokenGuard
    {
        $header = $definition['header'] ?? 'Authorization';
        $scheme = array_key_exists('scheme', $definition) ? $definition['scheme'] : 'Bearer';
        $query = $definition['query'] ?? null;
        $body = $definition['body'] ?? null;

        return new TokenGuard(
            $provider,
            is_string($header) ? $header : 'Authorization',
            is_string($scheme) ? $scheme : null,
            is_string($query) ? $query : null,
            is_string($body) ? $body : null,
        );
    }

    private function createProvider(string $name): UserProviderInterface
    {
        $definition = $this->providerDefinitions[$name] ?? throw new InvalidConfigException(sprintf('User provider "%s" is not defined.', $name));

        $class = $definition['class'] ?? null;
        if ($class !== null) {
            if (!is_string($class) || !is_a($class, UserProviderInterface::class, true)) {
                throw new InvalidConfigException(sprintf('The "class" of user provider "%s" must implement %s.', $name, UserProviderInterface::class));
            }

            return new $class(array_diff_key($definition, ['class' => true]), $this->container);
        }

        $driver = $definition['driver'] ?? null;
        if (!is_string($driver) || !in_array($driver, self::PROVIDER_DRIVERS, true)) {
            throw new InvalidConfigException(sprintf(
                'User provider "%s" needs a "driver" (%s) or a "class" implementing %s.',
                $name,
                implode(', ', self::PROVIDER_DRIVERS),
                UserProviderInterface::class,
            ));
        }

        if ($driver === 'array') {
            $users = $definition['users'] ?? [];
            if (!is_array($users)) {
                throw new InvalidConfigException(sprintf('The "users" of provider "%s" must be an array.', $name));
            }

            /** @var list<array<string, mixed>> $users */
            return new ArrayUserProvider($this->hasher(), array_values($users));
        }

        return new DatabaseUserProvider($this->connection($definition), $this->hasher(), $definition);
    }

    /**
     * @param array<string, mixed> $definition
     */
    private function connection(array $definition): ConnectionInterface
    {
        $name = $definition['connection'] ?? null;

        if (is_string($name)) {
            $manager = $this->container->get(DatabaseManagerInterface::class);
            if (!$manager instanceof DatabaseManagerInterface) {
                throw new InvalidConfigException(sprintf('The container entry %s must be a database manager to use a named connection.', DatabaseManagerInterface::class));
            }

            return $manager->connection($name);
        }

        $connection = $this->container->get(ConnectionInterface::class);
        if (!$connection instanceof ConnectionInterface) {
            throw new InvalidConfigException(sprintf('The container entry %s must be a database connection.', ConnectionInterface::class));
        }

        return $connection;
    }

    /**
     * @param array<string, mixed> $config
     *
     * @return array<string, array<string, mixed>>
     */
    private function definitions(array $config, string $key): array
    {
        $items = $config[$key] ?? [];
        if (!is_array($items)) {
            throw new InvalidConfigException(sprintf('The "%s" setting must be an array.', $key));
        }

        $definitions = [];
        foreach ($items as $name => $definition) {
            if (!is_array($definition)) {
                throw new InvalidConfigException(sprintf('The definition of "%s" in "%s" must be an array.', (string) $name, $key));
            }
            $definitions[(string) $name] = $definition;
        }

        return $definitions;
    }
}
