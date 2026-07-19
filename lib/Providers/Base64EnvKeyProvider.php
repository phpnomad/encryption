<?php

namespace PHPNomad\Encryption\Providers;

use PHPNomad\Encryption\Exceptions\KeyNotFoundException;
use PHPNomad\Encryption\Interfaces\KeyProvider;

/**
 * Resolves a single base64-encoded 32-byte key from an environment variable,
 * with an optional fallback to a base64 key file on disk.
 *
 * This mirrors the common "master key in the environment" deployment: set e.g.
 * APP_MASTER_KEY to a base64-encoded 32-byte key. Registered under one version
 * (default 1); compose several instances behind a KeyRing to rotate across
 * separate env vars, or use {@see ArrayKeyProvider} when you hold raw keys.
 */
final class Base64EnvKeyProvider implements KeyProvider
{
    private const KEY_BYTES = 32;

    private string $envVar;
    private ?string $keyFilePath;
    private int $version;

    public function __construct(string $envVar, ?string $keyFilePath = null, int $version = 1)
    {
        $this->envVar = $envVar;
        $this->keyFilePath = $keyFilePath;
        $this->version = $version;
    }

    public function getKey(int $version): string
    {
        if ($version !== $this->version) {
            throw new KeyNotFoundException(
                "Base64EnvKeyProvider only serves version {$this->version}, requested {$version}."
            );
        }

        $encoded = $this->resolveEncodedKey();
        $decoded = base64_decode($encoded, true);

        if ($decoded === false || strlen($decoded) !== self::KEY_BYTES) {
            throw new KeyNotFoundException(
                'Key must be a base64-encoded ' . self::KEY_BYTES . '-byte value.'
            );
        }

        return $decoded;
    }

    public function currentVersion(): int
    {
        return $this->version;
    }

    private function resolveEncodedKey(): string
    {
        $fromEnv = $_ENV[$this->envVar] ?? getenv($this->envVar) ?: '';
        if ($fromEnv !== '' && $fromEnv !== false) {
            return (string) $fromEnv;
        }

        if ($this->keyFilePath !== null && is_file($this->keyFilePath) && filesize($this->keyFilePath) > 0) {
            return trim((string) file_get_contents($this->keyFilePath));
        }

        throw new KeyNotFoundException(
            "No key found. Set the {$this->envVar} environment variable" .
            ($this->keyFilePath !== null ? " or create {$this->keyFilePath}." : '.')
        );
    }
}
