<?php

namespace PHPNomad\Encryption\Tests\Unit;

use PHPNomad\Encryption\Models\EncryptedValue;
use PHPUnit\Framework\TestCase;

class EncryptedValueTest extends TestCase
{
    public function test_exposes_all_constructor_fields(): void
    {
        $value = new EncryptedValue("cipher\x00bytes", "nonce\xffbytes", 3, 'opaque-cipher-tag');

        $this->assertSame("cipher\x00bytes", $value->getCiphertext());
        $this->assertSame("nonce\xffbytes", $value->getNonce());
        $this->assertSame(3, $value->getKeyVersion());
        $this->assertSame('opaque-cipher-tag', $value->getCipher());
    }

    public function test_defaults_key_version_to_one(): void
    {
        $value = new EncryptedValue('ciphertext', 'nonce');

        $this->assertSame(1, $value->getKeyVersion());
    }

    public function test_defaults_cipher_to_unknown(): void
    {
        $value = new EncryptedValue('ciphertext', 'nonce');

        $this->assertSame(EncryptedValue::CIPHER_UNKNOWN, $value->getCipher());
    }
}
