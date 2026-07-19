<?php

namespace PHPNomad\Encryption\Interfaces;

use PHPNomad\Encryption\Exceptions\DecryptionFailedException;
use PHPNomad\Encryption\Exceptions\EncryptionException;
use PHPNomad\Encryption\ValueObjects\EncryptedValue;

/**
 * Contract for a symmetric encryption strategy.
 *
 * Implementations MUST bind the ciphertext to the supplied $context using
 * authenticated encryption with associated data (AEAD) where the underlying
 * cipher supports it. The same $context passed at encrypt time must be passed
 * at decrypt time or decryption fails — this lets callers pin a ciphertext to
 * the row, column, or tenant it belongs to, so a value copied elsewhere will
 * not decrypt.
 */
interface EncryptionStrategy
{
    /**
     * Encrypt a plaintext string.
     *
     * @param string $plaintext The value to encrypt.
     * @param string $context   Associated data (AEAD) bound to the ciphertext.
     *                          Not secret, but authenticated. Defaults to empty.
     *
     * @throws EncryptionException When encryption cannot be performed.
     */
    public function encrypt(string $plaintext, string $context = ''): EncryptedValue;

    /**
     * Decrypt a previously-encrypted value.
     *
     * @param EncryptedValue $value   The ciphertext envelope.
     * @param string         $context The exact associated data used at encrypt time.
     *
     * @throws DecryptionFailedException When authentication or decryption fails.
     */
    public function decrypt(EncryptedValue $value, string $context = ''): string;
}
