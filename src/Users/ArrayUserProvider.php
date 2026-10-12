<?php

declare(strict_types=1);

namespace EchoFusion\AuthManager\Users;

use EchoFusion\Contracts\AuthManager\PasswordHasherInterface;
use EchoFusion\Contracts\AuthManager\UserInterface;
use EchoFusion\Contracts\AuthManager\UserProviderInterface;
use function hash;
use function hash_equals;
use function is_string;

/**
 * Users defined in an array (config, tests, small tools).
 *
 * Each entry needs an `id`; `password` is a password HASH, and `token` is an optional API token in plain text
 * that will be matched with a constant-time comparison. Every other key becomes a user attribute.
 *
 * <code>
 * new ArrayUserProvider($hasher, [
 *     ['id' => 1, 'email' => 'ann@example.com', 'password' => $hasher->hash('secret'), 'token' => 'abc123'],
 * ]);
 * </code>
 */
final class ArrayUserProvider implements UserProviderInterface
{
    /**
     * @param list<array<string, mixed>> $users
     */
    public function __construct(private readonly PasswordHasherInterface $hasher, private readonly array $users)
    {
    }

    public function findById(string|int $id): ?UserInterface
    {
        foreach ($this->users as $row) {
            if (isset($row['id']) && (string) $row['id'] === (string) $id) {
                return $this->make($row);
            }
        }

        return null;
    }

    public function findByCredentials(array $credentials): ?UserInterface
    {
        unset($credentials['password']);
        if ($credentials === []) {
            return null;
        }

        foreach ($this->users as $row) {
            foreach ($credentials as $key => $value) {
                if (!isset($row[$key]) || (string) $row[$key] !== (string) $value) {
                    continue 2;
                }
            }

            return $this->make($row);
        }

        return null;
    }

    public function validateCredentials(UserInterface $user, array $credentials): bool
    {
        $password = $credentials['password'] ?? null;
        $hash = $user->getAuthPassword();

        return is_string($password) && $hash !== null && $this->hasher->verify($password, $hash);
    }

    public function findByToken(string $token): ?UserInterface
    {
        foreach ($this->users as $row) {
            if (isset($row['token']) && is_string($row['token']) && hash_equals(hash('sha256', $row['token']), hash('sha256', $token))) {
                return $this->make($row);
            }
        }

        return null;
    }

    /**
     * @param array<string, mixed> $row
     */
    private function make(array $row): GenericUser
    {
        $password = $row['password'] ?? null;
        unset($row['password'], $row['token']);

        /** @var string|int $id */
        $id = $row['id'];

        return new GenericUser($id, is_string($password) ? $password : null, $row);
    }
}
