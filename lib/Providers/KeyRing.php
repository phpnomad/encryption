<?php

namespace PHPNomad\Encryption\Providers;

use PHPNomad\Encryption\Exceptions\KeyNotFoundException;
use PHPNomad\Encryption\Interfaces\KeyProvider;

/**
 * Composes several single-version {@see KeyProvider}s into one versioned ring.
 *
 * Useful when each key version lives behind its own provider — for example one
 * {@see Base64EnvKeyProvider} per environment variable (APP_KEY_V1, APP_KEY_V2)
 * during a rotation. Delegates each version to the provider that owns it.
 */
final class KeyRing implements KeyProvider
{
    /** @var array<int, KeyProvider> version => provider */
    private array $providers = [];
    private int $currentVersion;

    /**
     * @param array<int, KeyProvider> $providers      Map of version => provider.
     * @param int|null                $currentVersion Version for new encryption.
     *                                                 Defaults to the highest version.
     */
    public function __construct(array $providers, ?int $currentVersion = null)
    {
        if ($providers === []) {
            throw new KeyNotFoundException('KeyRing requires at least one provider.');
        }

        $this->providers = $providers;
        $this->currentVersion = $currentVersion ?? max(array_keys($providers));
    }

    public function getKey(int $version): string
    {
        if (!isset($this->providers[$version])) {
            throw new KeyNotFoundException("No provider registered for key version {$version}.");
        }

        return $this->providers[$version]->getKey($version);
    }

    public function currentVersion(): int
    {
        return $this->currentVersion;
    }
}
