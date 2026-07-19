<?php

namespace PHPNomad\Encryption\ValueObjects;

use InvalidArgumentException;

/**
 * Immutable envelope describing an encrypted value.
 *
 * Holds the raw (binary) ciphertext and nonce, the key version used to seal it,
 * and an identifier for the cipher that produced it. Provides conversions to and
 * from a compact self-describing string (for a single column / cache key) and to
 * and from an associative array (for spreading across dedicated DB columns).
 */
final class EncryptedValue
{
    /** XChaCha20-Poly1305 IETF AEAD — the default cipher. */
    public const CIPHER_XCHACHA = 'xchacha20poly1305_ietf';

    /** Legacy sodium_crypto_secretbox (XSalsa20-Poly1305, no associated data). */
    public const CIPHER_SECRETBOX = 'secretbox';

    /**
     * Cipher is not recorded alongside the ciphertext (e.g. legacy storage whose
     * schema predates a cipher column). Consumers may attempt detection.
     */
    public const CIPHER_UNKNOWN = '';

    /** Prefix marking a compact-string serialization of an EncryptedValue. */
    private const STRING_PREFIX = 'enc';

    /** Serialization format version for the compact string form. */
    private const STRING_VERSION = '1';

    private string $ciphertext;
    private string $nonce;
    private int $keyVersion;
    private string $cipher;

    /**
     * @param string $ciphertext Raw (binary) ciphertext.
     * @param string $nonce      Raw (binary) nonce.
     * @param int    $keyVersion Key version the value was sealed with.
     * @param string $cipher     One of the CIPHER_* constants.
     */
    public function __construct(
        string $ciphertext,
        string $nonce,
        int $keyVersion = 1,
        string $cipher = self::CIPHER_XCHACHA
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

    /**
     * Base64-encoded ciphertext, suitable for text columns / JSON.
     */
    public function getCiphertextBase64(): string
    {
        return base64_encode($this->ciphertext);
    }

    /**
     * Base64-encoded nonce, suitable for text columns / JSON.
     */
    public function getNonceBase64(): string
    {
        return base64_encode($this->nonce);
    }

    /**
     * Map to an associative array of base64 columns.
     *
     * @return array{ciphertext: string, nonce: string, keyVersion: int, cipher: string}
     */
    public function toArray(): array
    {
        return [
            'ciphertext' => $this->getCiphertextBase64(),
            'nonce' => $this->getNonceBase64(),
            'keyVersion' => $this->keyVersion,
            'cipher' => $this->cipher,
        ];
    }

    /**
     * Rebuild from an associative array produced by {@see toArray()}.
     *
     * The `cipher` key is optional; when absent the value is treated as
     * {@see CIPHER_UNKNOWN} so a migration-aware strategy can detect it.
     *
     * @param array<string, mixed> $data
     */
    public static function fromArray(array $data): self
    {
        foreach (['ciphertext', 'nonce'] as $required) {
            if (!isset($data[$required])) {
                throw new InvalidArgumentException("EncryptedValue array is missing '{$required}'.");
            }
        }

        $ciphertext = base64_decode((string) $data['ciphertext'], true);
        $nonce = base64_decode((string) $data['nonce'], true);

        if ($ciphertext === false || $nonce === false) {
            throw new InvalidArgumentException('EncryptedValue array contains invalid base64.');
        }

        return new self(
            $ciphertext,
            $nonce,
            (int) ($data['keyVersion'] ?? 1),
            (string) ($data['cipher'] ?? self::CIPHER_UNKNOWN)
        );
    }

    /**
     * Serialize to a compact, self-describing, URL-safe string:
     *
     *     enc:1:<cipher>:<keyVersion>:<b64url-nonce>:<b64url-ciphertext>
     *
     * Ideal for storing an encrypted value in a single column or cache key.
     */
    public function toString(): string
    {
        return implode(':', [
            self::STRING_PREFIX,
            self::STRING_VERSION,
            $this->cipher,
            (string) $this->keyVersion,
            self::base64UrlEncode($this->nonce),
            self::base64UrlEncode($this->ciphertext),
        ]);
    }

    public function __toString(): string
    {
        return $this->toString();
    }

    /**
     * Rebuild from the compact string produced by {@see toString()}.
     */
    public static function fromString(string $value): self
    {
        $parts = explode(':', $value, 6);

        if (count($parts) !== 6 || $parts[0] !== self::STRING_PREFIX) {
            throw new InvalidArgumentException('Malformed EncryptedValue string.');
        }

        [, $version, $cipher, $keyVersion, $nonce, $ciphertext] = $parts;

        if ($version !== self::STRING_VERSION) {
            throw new InvalidArgumentException("Unsupported EncryptedValue string version '{$version}'.");
        }

        $decodedNonce = self::base64UrlDecode($nonce);
        $decodedCiphertext = self::base64UrlDecode($ciphertext);

        if ($decodedNonce === false || $decodedCiphertext === false) {
            throw new InvalidArgumentException('EncryptedValue string contains invalid base64.');
        }

        return new self($decodedCiphertext, $decodedNonce, (int) $keyVersion, $cipher);
    }

    /**
     * Cheap check that a string looks like a serialized EncryptedValue, so
     * callers can decide whether a stored field is already encrypted.
     */
    public static function isEncryptedString(string $value): bool
    {
        return str_starts_with($value, self::STRING_PREFIX . ':' . self::STRING_VERSION . ':');
    }

    private static function base64UrlEncode(string $raw): string
    {
        return rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');
    }

    /**
     * @return string|false
     */
    private static function base64UrlDecode(string $encoded)
    {
        return base64_decode(strtr($encoded, '-_', '+/'), true);
    }
}
