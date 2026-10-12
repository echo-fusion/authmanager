<?php

declare(strict_types=1);

namespace EchoFusion\AuthManager\Users;

use EchoFusion\AuthManager\Exceptions\AuthException;
use EchoFusion\AuthManager\Exceptions\InvalidConfigException;
use EchoFusion\Contracts\AuthManager\PasswordHasherInterface;
use EchoFusion\Contracts\AuthManager\UserInterface;
use EchoFusion\Contracts\AuthManager\UserProviderInterface;
use EchoFusion\Contracts\DatabaseManager\ConnectionInterface;
use function array_fill;
use function array_key_exists;
use function array_keys;
use function array_values;
use function count;
use function get_debug_type;
use function hash;
use function implode;
use function is_int;
use function is_string;
use function preg_match;
use function sprintf;

/**
 * Users stored in a database table, read through the ConnectionInterface contract
 * (PDO, Doctrine DBAL ... anything that implements it).
 *
 * Options: `table` (users), `id` (id), `password` (password), `token` (api_token, set to null to disable
 * token lookups). API tokens are stored as a SHA-256 hash, never in plain text: save `hash('sha256', $token)`.
 * Table and column names are validated; values are always bound.
 */
final class DatabaseUserProvider implements UserProviderInterface
{
    private readonly string $table;

    private readonly string $idColumn;

    private readonly string $passwordColumn;

    private readonly ?string $tokenColumn;

    /**
     * @param array<string, mixed> $options
     *
     * @throws InvalidConfigException for an invalid table or column name
     */
    public function __construct(
        private readonly ConnectionInterface $connection,
        private readonly PasswordHasherInterface $hasher,
        array $options = [],
    ) {
        $this->table = self::identifier($options['table'] ?? 'users');
        $this->idColumn = self::identifier($options['id'] ?? 'id');
        $this->passwordColumn = self::identifier($options['password'] ?? 'password');
        $this->tokenColumn = array_key_exists('token', $options) && $options['token'] === null ? null : self::identifier($options['token'] ?? 'api_token');
    }

    public function findById(string|int $id): ?UserInterface
    {
        return $this->make($this->connection->fetchOne(
            sprintf('SELECT * FROM %s WHERE %s = ? LIMIT 1', $this->table, $this->idColumn),
            [$id],
        ));
    }

    public function findByCredentials(array $credentials): ?UserInterface
    {
        unset($credentials['password']);
        if ($credentials === []) {
            return null;
        }

        $conditions = [];
        foreach (array_keys($credentials) as $column) {
            $conditions[] = self::identifier($column) . ' = ?';
        }

        return $this->make($this->connection->fetchOne(
            sprintf('SELECT * FROM %s WHERE %s LIMIT 1', $this->table, implode(' AND ', $conditions)),
            array_values($credentials),
        ));
    }

    public function validateCredentials(UserInterface $user, array $credentials): bool
    {
        $password = $credentials['password'] ?? null;
        $hash = $user->getAuthPassword();

        return is_string($password) && $hash !== null && $this->hasher->verify($password, $hash);
    }

    public function findByToken(string $token): ?UserInterface
    {
        if ($this->tokenColumn === null || $token === '') {
            return null;
        }

        return $this->make($this->connection->fetchOne(
            sprintf('SELECT * FROM %s WHERE %s = ? LIMIT 1', $this->table, $this->tokenColumn),
            [hash('sha256', $token)],
        ));
    }

    /**
     * Insert a user; a `password` attribute is hashed before it is stored.
     *
     * @param array<string, mixed> $attributes column => value, including `password`
     *
     * @throws AuthException
     */
    public function create(array $attributes): UserInterface
    {
        if (isset($attributes['password']) && is_string($attributes['password'])) {
            $attributes[$this->passwordColumn] = $this->hasher->hash($attributes['password']);
            if ($this->passwordColumn !== 'password') {
                unset($attributes['password']);
            }
        }
        if ($attributes === []) {
            throw new AuthException('A user needs at least one attribute.');
        }

        $columns = [];
        foreach (array_keys($attributes) as $column) {
            $columns[] = self::identifier($column);
        }

        $this->connection->execute(
            sprintf('INSERT INTO %s (%s) VALUES (%s)', $this->table, implode(', ', $columns), implode(', ', array_fill(0, count($columns), '?'))),
            array_values($attributes),
        );

        $user = $this->findById($this->connection->lastInsertId());

        return $user ?? throw new AuthException('The user was inserted but could not be read back.');
    }

    /**
     * @param array<string, mixed>|null $row
     */
    private function make(?array $row): ?GenericUser
    {
        if ($row === null) {
            return null;
        }

        $password = $row[$this->passwordColumn] ?? null;
        $id = $row[$this->idColumn] ?? null;
        unset($row[$this->passwordColumn]);
        if ($this->tokenColumn !== null) {
            unset($row[$this->tokenColumn]);
        }

        if (!is_string($id) && !is_int($id)) {
            return null;
        }

        return new GenericUser($id, is_string($password) ? $password : null, $row);
    }

    private static function identifier(mixed $name): string
    {
        if (!is_string($name) || preg_match('/^[A-Za-z_][A-Za-z0-9_]*$/', $name) !== 1) {
            throw new InvalidConfigException(sprintf('"%s" is not a valid table or column name.', is_string($name) ? $name : get_debug_type($name)));
        }

        return $name;
    }
}
