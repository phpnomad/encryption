<?php

namespace PHPNomad\Encryption\Tests\Fakes;

use PHPNomad\Encryption\Exceptions\DecryptionFailedException;
use PHPNomad\Encryption\Interfaces\EncryptionStrategy;
use PHPNomad\Encryption\Interfaces\KeyProvider;
use PHPNomad\Encryption\Models\EncryptedValue;

/**
 * A dependency-free, fully reversible {@see EncryptionStrategy} used to exercise
 * the contract package without pulling in a real cipher (no ext-sodium).
 *
 * It is NOT cryptographically meaningful — it exists only to satisfy the
 * contract's observable guarantees so the framework-agnostic pieces
 * (EncryptedValue, the key providers, rotation) can be tested in isolation:
 *
 *  - Round-trips plaintext through a keystream XOR (confidentiality stand-in).
 *  - Authenticates the ciphertext AND the caller-supplied $context with an
 *    HMAC, so a wrong key, a mismatched context, or tampered bytes all raise
 *    {@see DecryptionFailedException} — mirroring an AEAD's behavior.
 *  - Decrypts against the key version recorded on the value, so key rotation
 *    (encrypt-with-current / decrypt-against-stored) works.
 *
 * The real cipher lives in phpnomad/sodium-integration.
 */
final class ReversibleFakeStrategy implements EncryptionStrategy
{
    public const CIPHER_FAKE = 'fake-xor-hmac';

    private const TAG_BYTES = 32;

    private KeyProvider $keys;

    public function __construct(KeyProvider $keys)
    {
        $this->keys = $keys;
    }

    public function encrypt(string $plaintext, string $context = ''): EncryptedValue
    {
        $version = $this->keys->currentVersion();
        $key = $this->keys->getKey($version);

        $nonce = random_bytes(16);
        $body = $this->xorStream($plaintext, $key, $nonce);
        $tag = $this->tag($body, $context, $key, $nonce);

        return new EncryptedValue($tag . $body, $nonce, $version, self::CIPHER_FAKE);
    }

    public function decrypt(EncryptedValue $value, string $context = ''): string
    {
        $key = $this->keys->getKey($value->getKeyVersion());
        $raw = $value->getCiphertext();

        $tag = substr($raw, 0, self::TAG_BYTES);
        $body = substr($raw, self::TAG_BYTES);

        $expected = $this->tag($body, $context, $key, $value->getNonce());

        if (!hash_equals($expected, $tag)) {
            throw new DecryptionFailedException(
                'Decryption failed: wrong key, mismatched context, or corrupted data.'
            );
        }

        return $this->xorStream($body, $key, $value->getNonce());
    }

    private function tag(string $body, string $context, string $key, string $nonce): string
    {
        return hash_hmac('sha256', $nonce . "\0" . $context . "\0" . $body, $key, true);
    }

    private function xorStream(string $data, string $key, string $nonce): string
    {
        $pad = '';
        $counter = 0;

        while (strlen($pad) < strlen($data)) {
            $pad .= hash('sha256', $key . $nonce . $counter, true);
            $counter++;
        }

        return $data ^ substr($pad, 0, strlen($data));
    }
}
