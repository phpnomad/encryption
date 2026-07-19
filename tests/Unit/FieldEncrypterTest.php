<?php

namespace PHPNomad\Encryption\Tests\Unit;

use PHPNomad\Encryption\Exceptions\DecryptionFailedException;
use PHPNomad\Encryption\Providers\ArrayKeyProvider;
use PHPNomad\Encryption\Services\FieldEncrypter;
use PHPNomad\Encryption\Strategies\SodiumEncryptionStrategy;
use PHPNomad\Encryption\ValueObjects\EncryptedValue;
use PHPUnit\Framework\TestCase;

class FieldEncrypterTest extends TestCase
{
    private function encrypter(): FieldEncrypter
    {
        $strategy = new SodiumEncryptionStrategy(new ArrayKeyProvider([1 => random_bytes(32)]));

        return new FieldEncrypter($strategy, ['access_token', 'refresh_token']);
    }

    public function test_encrypts_marked_fields_and_leaves_others_alone(): void
    {
        $encrypter = $this->encrypter();

        $encrypted = $encrypter->encryptRow([
            'id' => 5,
            'access_token' => 'at-123',
            'refresh_token' => 'rt-456',
            'label' => 'GitHub',
        ], 'user:5');

        $this->assertSame(5, $encrypted['id']);
        $this->assertSame('GitHub', $encrypted['label']);
        $this->assertTrue(EncryptedValue::isEncryptedString($encrypted['access_token']));
        $this->assertTrue(EncryptedValue::isEncryptedString($encrypted['refresh_token']));
        $this->assertStringNotContainsString('at-123', $encrypted['access_token']);
    }

    public function test_round_trip_restores_plaintext(): void
    {
        $encrypter = $this->encrypter();
        $row = ['access_token' => 'at-123', 'refresh_token' => 'rt-456', 'label' => 'GitHub'];

        $decrypted = $encrypter->decryptRow($encrypter->encryptRow($row, 'user:5'), 'user:5');

        $this->assertSame($row, $decrypted);
    }

    public function test_decrypt_with_wrong_context_fails(): void
    {
        $encrypter = $this->encrypter();
        $encrypted = $encrypter->encryptRow(['access_token' => 'at-123'], 'user:5');

        $this->expectException(DecryptionFailedException::class);
        $encrypter->decryptRow($encrypted, 'user:6');
    }

    public function test_encrypt_is_idempotent(): void
    {
        $encrypter = $this->encrypter();

        $once = $encrypter->encryptRow(['access_token' => 'at-123'], 'ctx');
        $twice = $encrypter->encryptRow($once, 'ctx');

        $this->assertSame($once['access_token'], $twice['access_token']);
    }

    public function test_null_and_absent_fields_are_skipped(): void
    {
        $encrypter = $this->encrypter();

        $encrypted = $encrypter->encryptRow(['access_token' => null], 'ctx');

        $this->assertNull($encrypted['access_token']);
        $this->assertArrayNotHasKey('refresh_token', $encrypted);
    }

    public function test_field_context_prevents_cross_field_swap(): void
    {
        $encrypter = $this->encrypter();
        $encrypted = $encrypter->encryptRow([
            'access_token' => 'at-123',
            'refresh_token' => 'rt-456',
        ], 'user:5');

        // Swap the two ciphertexts between columns: decryption must reject them,
        // because each field's AEAD context is bound to its own field name.
        $swapped = [
            'access_token' => $encrypted['refresh_token'],
            'refresh_token' => $encrypted['access_token'],
        ];

        $this->expectException(DecryptionFailedException::class);
        $encrypter->decryptRow($swapped, 'user:5');
    }
}
