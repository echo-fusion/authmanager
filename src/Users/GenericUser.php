<?php

declare(strict_types=1);

namespace EchoFusion\AuthManager\Users;

use EchoFusion\Contracts\AuthManager\UserInterface;

/**
 * A user made of plain attributes. The password hash is kept apart and never shows up in {@see toArray()}.
 */
final class GenericUser implements UserInterface
{
    /**
     * @param array<string, mixed> $attributes everything except the password hash
     */
    public function __construct(
        private readonly string|int $id,
        private readonly ?string $passwordHash = null,
        private readonly array $attributes = [],
    ) {
    }

    public function getAuthIdentifier(): string|int
    {
        return $this->id;
    }

    public function getAuthPassword(): ?string
    {
        return $this->passwordHash;
    }

    public function get(string $attribute, mixed $default = null): mixed
    {
        return $this->attributes[$attribute] ?? $default;
    }

    public function __get(string $attribute): mixed
    {
        return $this->attributes[$attribute] ?? null;
    }

    public function __isset(string $attribute): bool
    {
        return isset($this->attributes[$attribute]);
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return $this->attributes;
    }
}
