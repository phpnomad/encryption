<?php

namespace PHPNomad\Encryption\Tests\Unit;

use InvalidArgumentException;
use PHPNomad\Encryption\ValueObjects\EncryptedValue;
use PHPUnit\Framework\TestCase;

class EncryptedValueTest extends TestCase
{
    public function test_array_round_trip_preserves_all_fields(): void
    {
        $value = new EncryptedValue("cipher\x00bytes", "nonce\xffbytes", 3, EncryptedValue::CIPHER_XCHACHA);

        $restored = EncryptedValue::fromArray($value->toArray());

        $this->assertSame($value->getCiphertext(), $restored->getCiphertext());
        $this->assertSame($value->getNonce(), $restored->getNonce());
        $this->assertSame(3, $restored->getKeyVersion());
        $this->assertSame(EncryptedValue::CIPHER_XCHACHA, $restored->getCipher());
    }

    public function test_string_round_trip_preserves_all_fields(): void
    {
        $value = new EncryptedValue(random_bytes(40), random_bytes(24), 7, EncryptedValue::CIPHER_XCHACHA);

        $restored = EncryptedValue::fromString($value->toString());

        $this->assertSame($value->getCiphertext(), $restored->getCiphertext());
        $this->assertSame($value->getNonce(), $restored->getNonce());
        $this->assertSame(7, $restored->getKeyVersion());
        $this->assertSame(EncryptedValue::CIPHER_XCHACHA, $restored->getCipher());
    }

    public function test_compact_string_is_url_safe(): void
    {
        $value = new EncryptedValue(random_bytes(64), random_bytes(24), 1);

        $this->assertMatchesRegularExpression('#^[A-Za-z0-9:_-]+$#', $value->toString());
    }

    public function test_from_array_without_cipher_is_unknown(): void
    {
        $value = EncryptedValue::fromArray([
            'ciphertext' => base64_encode('ct'),
            'nonce' => base64_encode('nonce'),
            'keyVersion' => 1,
        ]);

        $this->assertSame(EncryptedValue::CIPHER_UNKNOWN, $value->getCipher());
    }

    public function test_is_encrypted_string_detects_serialized_values(): void
    {
        $value = new EncryptedValue(random_bytes(20), random_bytes(24), 1);

        $this->assertTrue(EncryptedValue::isEncryptedString($value->toString()));
        $this->assertFalse(EncryptedValue::isEncryptedString('just a plain value'));
        $this->assertFalse(EncryptedValue::isEncryptedString(''));
    }

    public function test_from_string_rejects_malformed_input(): void
    {
        $this->expectException(InvalidArgumentException::class);
        EncryptedValue::fromString('not-an-encrypted-value');
    }

    public function test_from_array_rejects_missing_fields(): void
    {
        $this->expectException(InvalidArgumentException::class);
        EncryptedValue::fromArray(['nonce' => base64_encode('nonce')]);
    }
}
