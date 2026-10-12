<?php

declare(strict_types=1);

namespace EchoFusion\AuthManager\Tests;

use EchoFusion\AuthManager\Exceptions\AuthException;
use EchoFusion\AuthManager\Exceptions\InvalidConfigException;
use EchoFusion\AuthManager\Hashing\PasswordHasher;
use EchoFusion\Contracts\AuthManager\PasswordHasherInterface;
use PHPUnit\Framework\TestCase;
use function defined;
use function str_repeat;
use function str_starts_with;

final class HasherTest extends TestCase
{
    public function testHashAndVerifyWithBcrypt(): void
    {
        $hasher = new PasswordHasher('bcrypt', ['cost' => 4]);
        $hash = $hasher->hash('secret');

        $this->assertInstanceOf(PasswordHasherInterface::class, $hasher);
        $this->assertTrue(str_starts_with($hash, '$2y$04$'));
        $this->assertNotSame($hash, $hasher->hash('secret'), 'every hash gets its own salt');
        $this->assertTrue($hasher->verify('secret', $hash));
        $this->assertFalse($hasher->verify('Secret', $hash));
        $this->assertFalse($hasher->verify('', $hash));
        $this->assertFalse($hasher->verify('secret', ''));
    }

    public function testDefaultCostIs12(): void
    {
        $this->assertTrue(str_starts_with((new PasswordHasher())->hash('x'), '$2y$12$'));
    }

    public function testNeedsRehashWhenSettingsGetStronger(): void
    {
        $hash = (new PasswordHasher('bcrypt', ['cost' => 4]))->hash('secret');

        $this->assertFalse((new PasswordHasher('bcrypt', ['cost' => 4]))->needsRehash($hash));
        $this->assertTrue((new PasswordHasher('bcrypt', ['cost' => 5]))->needsRehash($hash));
    }

    public function testArgon2id(): void
    {
        if (!defined('PASSWORD_ARGON2ID')) {
            $this->markTestSkipped('argon2id is not available in this PHP build.');
        }

        $hasher = new PasswordHasher('argon2id', ['memory_cost' => 1024, 'time_cost' => 2, 'threads' => 1]);
        $hash = $hasher->hash('secret');

        $this->assertTrue(str_starts_with($hash, '$argon2id$'));
        $this->assertTrue($hasher->verify('secret', $hash));
        $this->assertSame(str_repeat('x', 100), str_repeat('x', 100));
        $this->assertTrue($hasher->verify(str_repeat('x', 100), $hasher->hash(str_repeat('x', 100))), 'argon2id has no 72 byte limit');
    }

    public function testEmptyPasswordsAreRejected(): void
    {
        $this->expectException(AuthException::class);
        $this->expectExceptionMessage('cannot be empty');

        (new PasswordHasher('bcrypt', ['cost' => 4]))->hash('');
    }

    public function testBcryptRejectsPasswordsThatWouldBeTruncated(): void
    {
        $hasher = new PasswordHasher('bcrypt', ['cost' => 4]);

        $this->assertNotSame('', $hasher->hash(str_repeat('a', 72)));

        $this->expectException(AuthException::class);
        $this->expectExceptionMessage('72 bytes');
        $hasher->hash(str_repeat('a', 73));
    }

    public function testUnknownAlgorithm(): void
    {
        $this->expectException(InvalidConfigException::class);
        $this->expectExceptionMessage('Unknown hashing algorithm "md5"');

        new PasswordHasher('md5');
    }

    public function testTheBcryptLimitIsCountedInBytesNotCharacters(): void
    {
        $hasher = new PasswordHasher('bcrypt', ['cost' => 4]);
        $persian36 = str_repeat('س', 36); // 36 characters, exactly 72 bytes
        $persian37 = str_repeat('س', 37); // 37 characters, 74 bytes: bcrypt would silently ignore the last bytes

        $this->assertTrue($hasher->verify($persian36, $hasher->hash($persian36)));

        $this->expectException(AuthException::class);
        $this->expectExceptionMessage('72 bytes');
        $hasher->hash($persian37);
    }
}
