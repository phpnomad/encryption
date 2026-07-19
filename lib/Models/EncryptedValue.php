<?php

namespace PHPNomad\Encryption\Models;

/**
 * Immutable value produced by an {@see \PHPNomad\Encryption\Interfaces\EncryptionStrategy}:
 * the raw (binary) ciphertext and nonce, the key version that sealed it, and an
 * opaque, strategy-owned discriminator identifying the cipher.
 *
 * This is pure data. How you persist or transport it — dedicated columns, a
 * serialized string, base64, JSON — is deliberately the caller's concern and
 * lives nowhere in this contract. The encryption contract does not assume, or
 * impose, any storage shape.
 */
final class EncryptedValue
{
    /**
     * No cipher discriminator is recorded on the value, and the neutral default.
     * The contract names no concrete ciphers: a strategy owns its own identifier
     * and passes it through the constructor, reading it back via {@see getCipher()}.
     * Empty means "unspecified" — a migration-aware strategy may attempt detection.
     */
    public const CIPHER_UNKNOWN = '';

    private string $ciphertext;
    private string $nonce;
    private int $keyVersion;
    private string $cipher;

    /**
     * @param string $ciphertext Raw (binary) ciphertext.
     * @param string $nonce      Raw (binary) nonce.
     * @param int    $keyVersion Key version the value was sealed with.
     * @param string $cipher     Opaque, strategy-owned cipher discriminator.
     *                           Defaults to {@see CIPHER_UNKNOWN} (unspecified).
     */
    public function __construct(
        string $ciphertext,
        string $nonce,
        int $keyVersion = 1,
        string $cipher = self::CIPHER_UNKNOWN
    ) {
        $this->ciphertext = $ciphertext;
        $this->nonce = $nonce;
        $this->keyVersion = $keyVersion;
        $this->cipher = $cipher;
    }

    public function getCiphertext(): string
    {
        return $this->ciphertext;
    }

    public function getNonce(): string
    {
        return $this->nonce;
    }

    public function getKeyVersion(): int
    {
        return $this->keyVersion;
    }

    public function getCipher(): string
    {
        return $this->cipher;
    }
}
