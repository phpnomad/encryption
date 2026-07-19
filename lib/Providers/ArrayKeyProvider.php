<?php

namespace PHPNomad\Encryption\Providers;

use PHPNomad\Encryption\Exceptions\KeyNotFoundException;
use PHPNomad\Encryption\Interfaces\KeyProvider;

/**
 * In-memory key ring: a map of version => raw key, with a designated current
 * version for new encryption.
 *
 * This is the primitive that makes rotation work — hold every past key version
 * that stored ciphertext still references, and point `currentVersion` at the
 * newest. Encrypt-with-current / decrypt-against-stored falls out for free.
 */
final class ArrayKeyProvider implements KeyProvider
{
    /** @var array<int, string> version => raw key */
    private array $keys;
    private int $currentVersion;

    /**
     * @param array<int, string> $keys           Map of version => raw (binary) key.
     * @param int|null           $currentVersion Version for new encryption.
     *                                            Defaults to the highest version present.
     */
    public function __construct(array $keys, ?int $currentVersion = null)
    {
        if ($keys === []) {
            throw new KeyNotFoundException('ArrayKeyProvider requires at least one key.');
        }

        $this->keys = $keys;
        $this->currentVersion = $currentVersion ?? max(array_keys($keys));
    }

    public function getKey(int $version): string
    {
        if (!isset($this->keys[$version])) {
            throw new KeyNotFoundException("No key registered for version {$version}.");
        }

        return $this->keys[$version];
    }

    public function currentVersion(): int
    {
        return $this->currentVersion;
    }

    /**
     * Return a new provider with an additional key version registered as the
     * current version — the encrypt side of a rotation.
     */
    public function withRotatedKey(int $version, string $key): self
    {
        return new self($this->keys + [$version => $key], $version);
    }
}
