<?php

declare(strict_types=1);

namespace EchoFusion\AuthManager\Hashing;

use EchoFusion\AuthManager\Exceptions\AuthException;
use EchoFusion\AuthManager\Exceptions\InvalidConfigException;
use EchoFusion\Contracts\AuthManager\PasswordHasherInterface;
use const PASSWORD_ARGON2ID;
use const PASSWORD_BCRYPT;
use function defined;
use function password_hash;
use function password_needs_rehash;
use function password_verify;
use function sprintf;
use function strlen;

/**
 * Password hashing on top of PHP's `password_*` functions, which salt for you.
 *
 * Algorithms: `bcrypt` (default, `cost` option, default 12) or `argon2id`
 * (options `memory_cost`, `time_cost`, `threads`). bcrypt only uses the first 72
 * bytes of a password, so longer ones are rejected instead of silently truncated.
 */
final class PasswordHasher implements PasswordHasherInterface
{
    private const BCRYPT_MAX_BYTES = 72;

    private readonly string|int $algorithm;

    /**
     * @var array<string, int>
     */
    private readonly array $options;

    /**
     * @param array<string, int> $options
     *
     * @throws InvalidConfigException
     */
    public function __construct(string $algorithm = 'bcrypt', array $options = [])
    {
        if ($algorithm === 'bcrypt') {
            $this->algorithm = PASSWORD_BCRYPT;
            $this->options = $options + ['cost' => 12];
        } elseif ($algorithm === 'argon2id') {
            if (!defined('PASSWORD_ARGON2ID')) {
                throw new InvalidConfigException('This PHP build does not support argon2id; use "bcrypt".');
            }
            $this->algorithm = PASSWORD_ARGON2ID;
            $this->options = $options;
        } else {
            throw new InvalidConfigException(sprintf('Unknown hashing algorithm "%s"; use "bcrypt" or "argon2id".', $algorithm));
        }
    }

    public function hash(string $plain): string
    {
        if ($plain === '') {
            throw new AuthException('A password cannot be empty.');
        }
        if ($this->algorithm === PASSWORD_BCRYPT && strlen($plain) > self::BCRYPT_MAX_BYTES) {
            throw new AuthException(sprintf('bcrypt only uses the first %d bytes of a password; use a shorter one.', self::BCRYPT_MAX_BYTES));
        }

        return password_hash($plain, $this->algorithm, $this->options);
    }

    public function verify(string $plain, string $hash): bool
    {
        return $plain !== '' && $hash !== '' && password_verify($plain, $hash);
    }

    public function needsRehash(string $hash): bool
    {
        return password_needs_rehash($hash, $this->algorithm, $this->options);
    }
}
