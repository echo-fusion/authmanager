<?php

declare(strict_types=1);

namespace EchoFusion\AuthManager\Tests;

use EchoFusion\AuthManager\Exceptions\AuthException;
use EchoFusion\AuthManager\Exceptions\InvalidConfigException;
use EchoFusion\AuthManager\Hashing\PasswordHasher;
use EchoFusion\AuthManager\Users\ArrayUserProvider;
use EchoFusion\AuthManager\Users\DatabaseUserProvider;
use EchoFusion\AuthManager\Users\GenericUser;
use EchoFusion\Contracts\AuthManager\UserProviderInterface;
use EchoFusion\DatabaseManager\Connections\PdoConnection;
use PHPUnit\Framework\TestCase;
use function hash;

final class UserProvidersTest extends TestCase
{
    private PasswordHasher $hasher;

    protected function setUp(): void
    {
        $this->hasher = new PasswordHasher('bcrypt', ['cost' => 4]);
    }

    public function testGenericUser(): void
    {
        $user = new GenericUser(7, 'hash', ['email' => 'a@b.c', 'role' => null]);

        $this->assertSame(7, $user->getAuthIdentifier());
        $this->assertSame('hash', $user->getAuthPassword());
        $this->assertSame('a@b.c', $user->get('email'));
        $this->assertSame('a@b.c', $user->email);
        $this->assertSame('d', $user->get('missing', 'd'));
        $this->assertNull($user->missing);
        $this->assertTrue(isset($user->email));
        $this->assertFalse(isset($user->role));
        $this->assertSame(['email' => 'a@b.c', 'role' => null], $user->toArray(), 'the hash is not part of the attributes');
        $this->assertNull((new GenericUser('x'))->getAuthPassword());
    }

    public function testArrayProvider(): void
    {
        $provider = new ArrayUserProvider($this->hasher, [
            ['id' => 1, 'email' => 'ann@example.com', 'name' => 'Ann', 'password' => $this->hasher->hash('secret'), 'token' => 'tok-1'],
            ['id' => 'b', 'email' => 'bob@example.com'],
        ]);

        $this->assertInstanceOf(UserProviderInterface::class, $provider);
        $this->assertSame(1, $provider->findById('1')?->getAuthIdentifier());
        $this->assertSame('b', $provider->findById('b')?->getAuthIdentifier());
        $this->assertNull($provider->findById(99));

        $ann = $provider->findByCredentials(['email' => 'ann@example.com', 'password' => 'ignored']);
        $this->assertInstanceOf(GenericUser::class, $ann);
        $this->assertSame('Ann', $ann->name);
        $this->assertNull($ann->password, 'hash and token never become attributes');
        $this->assertNull($provider->findByCredentials(['email' => 'nobody@example.com']));
        $this->assertNull($provider->findByCredentials(['password' => 'only-password']));
        $this->assertNull($provider->findByCredentials(['email' => 'ann@example.com', 'name' => 'Wrong']));

        $this->assertTrue($provider->validateCredentials($ann, ['password' => 'secret']));
        $this->assertFalse($provider->validateCredentials($ann, ['password' => 'wrong']));
        $this->assertFalse($provider->validateCredentials($ann, []));
        $this->assertFalse($provider->validateCredentials($ann, ['password' => 123]));
        $bob = $provider->findById('b');
        $this->assertNotNull($bob);
        $this->assertFalse($provider->validateCredentials($bob, ['password' => 'secret']), 'a user without a password cannot log in');

        $this->assertSame(1, $provider->findByToken('tok-1')?->getAuthIdentifier());
        $this->assertNull($provider->findByToken('tok-2'));
    }

    private function database(): DatabaseUserProvider
    {
        $db = new PdoConnection(['driver' => 'sqlite']);
        $db->execute('CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, email TEXT UNIQUE, password TEXT, api_token TEXT)');
        $db->execute('INSERT INTO users (name, email, password, api_token) VALUES (?, ?, ?, ?)', ['Ann', 'ann@example.com', $this->hasher->hash('secret'), hash('sha256', 'tok-1')]);

        return new DatabaseUserProvider($db, $this->hasher);
    }

    public function testDatabaseProvider(): void
    {
        $provider = $this->database();

        $ann = $provider->findById(1);
        $this->assertInstanceOf(GenericUser::class, $ann);
        $this->assertSame(1, $ann->getAuthIdentifier());
        $this->assertSame('Ann', $ann->name);
        $this->assertNull($ann->api_token, 'the token hash never becomes an attribute');
        $this->assertNull($provider->findById(99));

        $this->assertSame(1, $provider->findByCredentials(['email' => 'ann@example.com', 'password' => 'x'])?->getAuthIdentifier());
        $this->assertSame(1, $provider->findByCredentials(['email' => 'ann@example.com', 'name' => 'Ann'])?->getAuthIdentifier());
        $this->assertNull($provider->findByCredentials(['email' => 'nobody@example.com']));
        $this->assertNull($provider->findByCredentials(['password' => 'only']));

        $this->assertTrue($provider->validateCredentials($ann, ['password' => 'secret']));
        $this->assertFalse($provider->validateCredentials($ann, ['password' => 'nope']));
        $this->assertFalse($provider->validateCredentials($ann, []));

        $this->assertSame(1, $provider->findByToken('tok-1')?->getAuthIdentifier());
        $this->assertNull($provider->findByToken('tok-2'));
        $this->assertNull($provider->findByToken(''));
        $this->assertNull($provider->findByToken(hash('sha256', 'tok-1')), 'the stored hash is not a valid token');
    }

    public function testDatabaseProviderBindsValues(): void
    {
        $provider = $this->database();

        $this->assertNull($provider->findByCredentials(['email' => "x' OR '1'='1"]));
        $this->assertNull($provider->findByToken("x' OR '1'='1"));
        $this->assertNull($provider->findById('1 OR 1=1'));
    }

    public function testDatabaseProviderRejectsInvalidColumnNames(): void
    {
        $this->expectException(InvalidConfigException::class);

        $this->database()->findByCredentials(['email = 1 OR email' => 'x']);
    }

    public function testCreateHashesThePasswordAndReturnsTheUser(): void
    {
        $provider = $this->database();

        $user = $provider->create(['name' => 'Bob', 'email' => 'bob@example.com', 'password' => 'hunter22']);

        $this->assertSame(2, $user->getAuthIdentifier());
        $this->assertNotSame('hunter22', $user->getAuthPassword());
        $this->assertTrue($provider->validateCredentials($user, ['password' => 'hunter22']));
    }

    public function testCreateWithoutAttributesFails(): void
    {
        $this->expectException(AuthException::class);

        $this->database()->create([]);
    }

    public function testCustomColumnsAndDisabledTokens(): void
    {
        $db = new PdoConnection(['driver' => 'sqlite']);
        $db->execute('CREATE TABLE accounts (account_id INTEGER PRIMARY KEY AUTOINCREMENT, login TEXT, pwd TEXT)');
        $provider = new DatabaseUserProvider($db, $this->hasher, ['table' => 'accounts', 'id' => 'account_id', 'password' => 'pwd', 'token' => null]);

        $user = $provider->create(['login' => 'ann', 'password' => 'secret']);

        $this->assertSame(1, $user->getAuthIdentifier());
        $this->assertTrue($provider->validateCredentials($user, ['password' => 'secret']));
        $this->assertSame(1, $provider->findByCredentials(['login' => 'ann'])?->getAuthIdentifier());
        $this->assertNull($provider->findByToken('anything'));
    }

    /**
     * @dataProvider invalidOptions
     *
     * @param array<string, mixed> $options
     */
    public function testInvalidOptions(array $options): void
    {
        $this->expectException(InvalidConfigException::class);

        new DatabaseUserProvider(new PdoConnection(['driver' => 'sqlite']), $this->hasher, $options);
    }

    /**
     * @return array<string, array{array<string, mixed>}>
     */
    public function invalidOptions(): array
    {
        return [
            'table' => [['table' => 'users; DROP TABLE users']],
            'id' => [['id' => 'id OR 1']],
            'password' => [['password' => 'a b']],
            'token' => [['token' => 'a-b']],
            'not a string' => [['table' => 5]],
        ];
    }
}
