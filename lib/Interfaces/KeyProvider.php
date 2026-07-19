<?php

namespace PHPNomad\Encryption\Interfaces;

use PHPNomad\Encryption\Exceptions\KeyNotFoundException;

/**
 * Supplies raw symmetric keys addressed by version.
 *
 * Versioning enables key rotation: new values are encrypted with the current
 * version, while existing values remain decryptable against the version they
 * were sealed with. Implementations must retain every version still referenced
 * by stored ciphertext.
 */
interface KeyProvider
{
    /**
     * Return the raw (binary) key for the given version.
     *
     * @param int $version The key version to resolve.
     *
     * @return string A raw 32-byte key.
     *
     * @throws KeyNotFoundException When no key exists for the version.
     */
    public function getKey(int $version): string;

    /**
     * The version that new values should be encrypted with.
     */
    public function currentVersion(): int;
}
