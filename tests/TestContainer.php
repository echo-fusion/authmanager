<?php

declare(strict_types=1);

namespace EchoFusion\AuthManager\Tests;

use EchoFusion\Contracts\ServiceManager\SettableContainerInterface;
use Psr\Container\NotFoundExceptionInterface;
use RuntimeException;
use function array_key_exists;
use function is_callable;

final class TestContainer implements SettableContainerInterface
{
    /**
     * @var array<string, callable>
     */
    private array $factories = [];

    /**
     * @var array<string, mixed>
     */
    private array $instances = [];

    public function set(string $id, callable|string $service, bool $shared = false): void
    {
        $this->factories[$id] = is_callable($service) ? $service : static fn () => new $service();
        unset($this->instances[$id]);
    }

    public function get(string $id): mixed
    {
        if (!$this->has($id)) {
            throw new class('missing ' . $id) extends RuntimeException implements NotFoundExceptionInterface {
            };
        }

        return $this->instances[$id] ??= ($this->factories[$id])();
    }

    public function has(string $id): bool
    {
        return array_key_exists($id, $this->factories);
    }
}
