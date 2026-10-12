<?php

declare(strict_types=1);

namespace EchoFusion\AuthManager\Tests;

use EchoFusion\AuthManager\AuthManager;
use EchoFusion\AuthManager\Exceptions\GuardNotFoundException;
use EchoFusion\AuthManager\Exceptions\InvalidConfigException;
use EchoFusion\AuthManager\Guards\SessionGuard;
use EchoFusion\AuthManager\Guards\TokenGuard;
use EchoFusion\AuthManager\Hashing\PasswordHasher;
use EchoFusion\AuthManager\Users\ArrayUserProvider;
use EchoFusion\AuthManager\Users\DatabaseUserProvider;
use EchoFusion\Contracts\AuthManager\AuthManagerInterface;
use EchoFusion\Contracts\AuthManager\GuardInterface;
use EchoFusion\Contracts\AuthManager\UserInterface;
use EchoFusion\Contracts\AuthManager\UserProviderInterface;
use EchoFusion\Contracts\DatabaseManager\ConnectionInterface;
use EchoFusion\Contracts\DatabaseManager\DatabaseManagerInterface;
use EchoFusion\Contracts\SessionManager\SessionInterface;
use EchoFusion\DatabaseManager\DatabaseManager;
use EchoFusion\SessionManager\ArraySession;
use PHPUnit\Framework\TestCase;
use Psr\Container\ContainerInterface;
use stdClass;

final class AuthManagerTest extends TestCase
{
    private TestContainer $container;

    protected function setUp(): void
    {
        $databases = new DatabaseManager(['connections' => ['main' => ['driver' => 'sqlite'], 'other' => ['driver' => 'sqlite']]]);
        $databases->connection('main')->execute('CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT, password TEXT, api_token TEXT)');
        $databases->connection('other')->execute('CREATE TABLE members (id INTEGER PRIMARY KEY, email TEXT, password TEXT, api_token TEXT)');

        $this->container = new TestContainer();
        $this->container->set(SessionInterface::class, fn () => new ArraySession());
        $this->container->set(ConnectionInterface::class, fn () => $databases->connection());
        $this->container->set(DatabaseManagerInterface::class, fn () => $databases);
    }

    /**
     * @param array<string, mixed> $config
     */
    private function manager(array $config): AuthManager
    {
        return new AuthManager($this->container, $config);
    }

    public function testGuardsAreChosenByConfigAndReused(): void
    {
        $manager = $this->manager([
            'default' => 'api',
            'guards' => [
                'web' => ['driver' => 'session', 'provider' => 'users', 'key' => 'uid'],
                'api' => ['driver' => 'token', 'provider' => 'users', 'header' => 'X-Api-Key', 'scheme' => null, 'query' => 'api_token', 'body' => 'token'],
            ],
            'providers' => ['users' => ['driver' => 'database']],
        ]);

        $this->assertInstanceOf(AuthManagerInterface::class, $manager);
        $this->assertSame('api', $manager->getDefaultGuardName());
        $this->assertTrue($manager->has('web'));
        $this->assertFalse($manager->has('nope'));
        $this->assertInstanceOf(TokenGuard::class, $manager->guard());
        $this->assertInstanceOf(SessionGuard::class, $manager->guard('web'));
        $this->assertSame($manager->guard('web'), $manager->guard('web'));
        $this->assertInstanceOf(DatabaseUserProvider::class, $manager->provider('users'));
        $this->assertSame($manager->provider('users'), $manager->provider('users'));
    }

    public function testDefaultsToTheFirstGuard(): void
    {
        $manager = $this->manager([
            'guards' => ['first' => ['driver' => 'session', 'provider' => 'p'], 'second' => ['driver' => 'token', 'provider' => 'p']],
            'providers' => ['p' => ['driver' => 'array', 'users' => []]],
        ]);

        $this->assertSame('first', $manager->getDefaultGuardName());
        $this->assertInstanceOf(ArrayUserProvider::class, $manager->provider('p'));
    }

    public function testStatefulGuardRefusesStatelessGuards(): void
    {
        $manager = $this->manager([
            'guards' => ['web' => ['driver' => 'session', 'provider' => 'p'], 'api' => ['driver' => 'token', 'provider' => 'p']],
            'providers' => ['p' => ['driver' => 'array', 'users' => []]],
        ]);

        $this->assertInstanceOf(SessionGuard::class, $manager->statefulGuard('web'));

        $this->expectException(InvalidConfigException::class);
        $this->expectExceptionMessage('Guard "api" is stateless');
        $manager->statefulGuard('api');
    }

    public function testTheHasherIsConfigurable(): void
    {
        $manager = $this->manager(['hasher' => ['algorithm' => 'bcrypt', 'options' => ['cost' => 4]]]);

        $this->assertInstanceOf(PasswordHasher::class, $manager->hasher());
        $this->assertSame($manager->hasher(), $manager->hasher());
        $this->assertStringStartsWith('$2y$04$', $manager->hasher()->hash('x'));
        $this->assertStringStartsWith('$2y$12$', $this->manager([])->hasher()->hash('x'));
    }

    public function testANamedDatabaseConnectionIsUsed(): void
    {
        $manager = $this->manager([
            'guards' => ['web' => ['driver' => 'session', 'provider' => 'members']],
            'providers' => ['members' => ['driver' => 'database', 'connection' => 'other', 'table' => 'members']],
        ]);
        /** @var DatabaseUserProvider $provider */
        $provider = $manager->provider('members');

        $this->assertSame(1, $provider->create(['email' => 'a@b.c', 'password' => 'secret'])->getAuthIdentifier());
        $this->assertNull($this->container->get(ConnectionInterface::class)->fetchOne('SELECT * FROM users'), 'the default connection was not touched');
    }

    public function testCustomGuardAndProviderClassesFromConfig(): void
    {
        $manager = $this->manager([
            'guards' => ['custom' => ['class' => CustomGuard::class, 'provider' => 'mine', 'flag' => 'on']],
            'providers' => ['mine' => ['class' => CustomProvider::class, 'color' => 'red']],
        ]);

        /** @var CustomGuard $guard */
        $guard = $manager->guard('custom');
        $this->assertInstanceOf(CustomGuard::class, $guard);
        $this->assertSame(['provider' => 'mine', 'flag' => 'on'], $guard->definition);
        $this->assertSame($this->container, $guard->container);
        $this->assertInstanceOf(CustomProvider::class, $guard->provider);
        $this->assertSame(['color' => 'red'], $guard->provider->definition);
    }

    public function testUnknownGuard(): void
    {
        $this->expectException(GuardNotFoundException::class);
        $this->expectExceptionMessage('Authentication guard "nope" is not defined.');

        $this->manager(['guards' => ['web' => ['driver' => 'session', 'provider' => 'p']]])->guard('nope');
    }

    public function testNothingConfigured(): void
    {
        $this->expectException(InvalidConfigException::class);
        $this->expectExceptionMessage('No authentication guards are configured.');

        $this->manager([])->guard();
    }

    public function testReconfigureDropsExistingInstances(): void
    {
        $config = ['guards' => ['web' => ['driver' => 'session', 'provider' => 'p']], 'providers' => ['p' => ['driver' => 'array', 'users' => []]]];
        $manager = $this->manager($config);
        $first = $manager->guard();

        $manager->configure($config);

        $this->assertNotSame($first, $manager->guard());
    }

    /**
     * @dataProvider invalidConfigs
     *
     * @param array<string, mixed> $config
     */
    public function testInvalidConfig(array $config, string $message): void
    {
        $this->expectException(InvalidConfigException::class);
        $this->expectExceptionMessage($message);

        $manager = $this->manager($config);
        $manager->guard('g');
    }

    /**
     * @return array<string, array{array<string, mixed>, string}>
     */
    public function invalidConfigs(): array
    {
        $provider = ['providers' => ['p' => ['driver' => 'array', 'users' => []]]];

        return [
            'guards not array' => [['guards' => 'x'], '"guards" setting must be an array'],
            'definition not array' => [['guards' => ['g' => 'x']], 'definition of "g" in "guards" must be an array'],
            'unknown default' => [['default' => 'zzz', 'guards' => ['g' => ['driver' => 'session', 'provider' => 'p']]], 'default guard "zzz"'],
            'hasher not array' => [['hasher' => 'x'], '"hasher" setting must be an array'],
            'no provider' => [['guards' => ['g' => ['driver' => 'session']]], 'needs a "provider"'],
            'unknown provider' => [['guards' => ['g' => ['driver' => 'session', 'provider' => 'zzz']]], 'User provider "zzz" is not defined'],
            'no guard driver' => [['guards' => ['g' => ['provider' => 'p']]] + $provider, 'needs a "driver"'],
            'bad guard driver' => [['guards' => ['g' => ['driver' => 'magic', 'provider' => 'p']]] + $provider, 'needs a "driver"'],
            'guard class invalid' => [['guards' => ['g' => ['class' => stdClass::class, 'provider' => 'p']]] + $provider, 'must implement'],
            'guard class not string' => [['guards' => ['g' => ['class' => 5, 'provider' => 'p']]] + $provider, 'must implement'],
            'no provider driver' => [['guards' => ['g' => ['driver' => 'session', 'provider' => 'p']], 'providers' => ['p' => []]], 'needs a "driver"'],
            'bad provider driver' => [['guards' => ['g' => ['driver' => 'session', 'provider' => 'p']], 'providers' => ['p' => ['driver' => 'ldap']]], 'needs a "driver"'],
            'provider class invalid' => [['guards' => ['g' => ['driver' => 'session', 'provider' => 'p']], 'providers' => ['p' => ['class' => stdClass::class]]], 'must implement'],
            'array users invalid' => [['guards' => ['g' => ['driver' => 'session', 'provider' => 'p']], 'providers' => ['p' => ['driver' => 'array', 'users' => 'x']]], '"users" of provider "p" must be an array'],
            'hasher invalid' => [['hasher' => ['algorithm' => 5]] + ['guards' => ['g' => ['driver' => 'session', 'provider' => 'p']], 'providers' => ['p' => ['driver' => 'array', 'users' => []]]], 'needs a string "algorithm"'],
        ];
    }

    public function testContainerEntriesOfTheWrongTypeAreReported(): void
    {
        $container = new TestContainer();
        $container->set(SessionInterface::class, fn () => new stdClass());
        $container->set(ConnectionInterface::class, fn () => new stdClass());
        $container->set(DatabaseManagerInterface::class, fn () => new stdClass());
        $config = [
            'guards' => ['s' => ['driver' => 'session', 'provider' => 'a'], 'd' => ['driver' => 'token', 'provider' => 'db'], 'n' => ['driver' => 'token', 'provider' => 'named']],
            'providers' => ['a' => ['driver' => 'array', 'users' => []], 'db' => ['driver' => 'database'], 'named' => ['driver' => 'database', 'connection' => 'x']],
        ];

        foreach ([['s', 'must be a session'], ['d', 'must be a database connection'], ['n', 'must be a database manager']] as [$guard, $message]) {
            try {
                (new AuthManager($container, $config))->guard($guard);
                $this->fail('Expected InvalidConfigException for ' . $guard);
            } catch (InvalidConfigException $e) {
                $this->assertStringContainsString($message, $e->getMessage());
            }
        }
    }
}

final class CustomGuard implements GuardInterface
{
    /**
     * @param array<string, mixed> $definition
     */
    public function __construct(
        public readonly UserProviderInterface $provider,
        public readonly array $definition,
        public readonly ContainerInterface $container,
    ) {
    }

    public function user(): ?UserInterface
    {
        return null;
    }

    public function check(): bool
    {
        return false;
    }

    public function guest(): bool
    {
        return true;
    }

    public function id(): string|int|null
    {
        return null;
    }

    public function validate(array $credentials): bool
    {
        return false;
    }
}

final class CustomProvider implements UserProviderInterface
{
    /**
     * @param array<string, mixed> $definition
     */
    public function __construct(public readonly array $definition, public readonly ContainerInterface $container)
    {
    }

    public function findById(string|int $id): ?UserInterface
    {
        return null;
    }

    public function findByCredentials(array $credentials): ?UserInterface
    {
        return null;
    }

    public function validateCredentials(UserInterface $user, array $credentials): bool
    {
        return false;
    }

    public function findByToken(string $token): ?UserInterface
    {
        return null;
    }
}
