<?php

namespace PHPNomad\Encryption\Tests\Unit;

use PHPNomad\Encryption\Exceptions\DecryptionFailedException;
use PHPNomad\Encryption\Providers\ArrayKeyProvider;
use PHPNomad\Encryption\Providers\Base64EnvKeyProvider;
use PHPNomad\Encryption\Providers\KeyRing;
use PHPNomad\Encryption\Tests\Fakes\ReversibleFakeStrategy;
use PHPNomad\Encryption\ValueObjects\EncryptedValue;
use PHPUnit\Framework\TestCase;

/**
 * Exercises the framework-agnostic contract surface — the EncryptionStrategy
 * behavior every integration must uphold, plus key rotation through the
 * providers — using the in-package fake strategy. No cipher, no ext-sodium.
 * The real libsodium implementation is verified in phpnomad/sodium-integration.
 */
class EncryptionContractTest extends TestCase
{
    private function strategy(?ArrayKeyProvider $keys = null): ReversibleFakeStrategy
    {
        return new ReversibleFakeStrategy($keys ?? new ArrayKeyProvider([1 => random_bytes(32)]));
    }

    public function test_encrypt_decrypt_round_trip(): void
    {
        $strategy = $this->strategy();

        $encrypted = $strategy->encrypt('sk-live-super-secret');

        $this->assertNotSame('sk-live-super-secret', $encrypted->getCiphertext());
        $this->assertSame('sk-live-super-secret', $strategy->decrypt($encrypted));
    }

    public function test_context_binds_ciphertext(): void
    {
        $strategy = $this->strategy();

        $encrypted = $strategy->encrypt('secret', 'tenant:42:column:token');

        $this->assertSame('secret', $strategy->decrypt($encrypted, 'tenant:42:column:token'));

        // A different context must fail — the value cannot be replayed elsewhere.
        $this->expectException(DecryptionFailedException::class);
        $strategy->decrypt($encrypted, 'tenant:99:column:token');
    }

    public function test_tampered_ciphertext_fails(): void
    {
        $strategy = $this->strategy();
        $encrypted = $strategy->encrypt('secret');

        $bytes = $encrypted->getCiphertext();
        $bytes[strlen($bytes) - 1] = $bytes[strlen($bytes) - 1] === "\x00" ? "\x01" : "\x00";
        $tampered = new EncryptedValue(
            $bytes,
            $encrypted->getNonce(),
            $encrypted->getKeyVersion(),
            $encrypted->getCipher()
        );

        $this->expectException(DecryptionFailedException::class);
        $strategy->decrypt($tampered);
    }

    public function test_wrong_key_fails(): void
    {
        $encrypted = $this->strategy(new ArrayKeyProvider([1 => random_bytes(32)]))->encrypt('secret');

        $this->expectException(DecryptionFailedException::class);
        $this->strategy(new ArrayKeyProvider([1 => random_bytes(32)]))->decrypt($encrypted);
    }

    public function test_serialized_value_survives_a_round_trip_through_a_column(): void
    {
        $strategy = $this->strategy();

        $column = $strategy->encrypt('secret', 'ctx')->toString();

        $this->assertTrue(EncryptedValue::isEncryptedString($column));
        $this->assertSame('secret', $strategy->decrypt(EncryptedValue::fromString($column), 'ctx'));
    }

    public function test_key_rotation_via_array_key_provider(): void
    {
        $v1 = random_bytes(32);
        $v2 = random_bytes(32);

        // Value sealed under v1 while v1 was current.
        $sealedUnderV1 = $this->strategy(new ArrayKeyProvider([1 => $v1], 1))->encrypt('old-value');
        $this->assertSame(1, $sealedUnderV1->getKeyVersion());

        // Rotate: v2 is now current, but v1 is still held for old ciphertext.
        $rotated = $this->strategy(new ArrayKeyProvider([1 => $v1, 2 => $v2], 2));

        $sealedUnderV2 = $rotated->encrypt('new-value');
        $this->assertSame(2, $sealedUnderV2->getKeyVersion());

        // Both old and new values still decrypt after rotation.
        $this->assertSame('new-value', $rotated->decrypt($sealedUnderV2));
        $this->assertSame('old-value', $rotated->decrypt($sealedUnderV1));
    }

    public function test_key_rotation_via_key_ring_of_per_version_providers(): void
    {
        $v1 = base64_encode(random_bytes(32));
        $v2 = base64_encode(random_bytes(32));

        $_ENV['APP_KEY_V1'] = $v1;
        $_ENV['APP_KEY_V2'] = $v2;

        try {
            // v1 is current: seal a value against a single-version ring.
            $ringV1 = new KeyRing([1 => new Base64EnvKeyProvider('APP_KEY_V1', null, 1)], 1);
            $sealedUnderV1 = (new ReversibleFakeStrategy($ringV1))->encrypt('old');
            $this->assertSame(1, $sealedUnderV1->getKeyVersion());

            // Compose both versions behind one ring, v2 current.
            $ring = new KeyRing([
                1 => new Base64EnvKeyProvider('APP_KEY_V1', null, 1),
                2 => new Base64EnvKeyProvider('APP_KEY_V2', null, 2),
            ], 2);
            $rotated = new ReversibleFakeStrategy($ring);

            $sealedUnderV2 = $rotated->encrypt('new');
            $this->assertSame(2, $sealedUnderV2->getKeyVersion());

            // New writes use v2; the old v1 value still decrypts via the ring.
            $this->assertSame('new', $rotated->decrypt($sealedUnderV2));
            $this->assertSame('old', $rotated->decrypt($sealedUnderV1));
        } finally {
            unset($_ENV['APP_KEY_V1'], $_ENV['APP_KEY_V2']);
        }
    }
}
