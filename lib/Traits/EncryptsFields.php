<?php

namespace PHPNomad\Encryption\Traits;

use PHPNomad\Encryption\Interfaces\EncryptionStrategy;
use PHPNomad\Encryption\Services\FieldEncrypter;

/**
 * Drop-in field-level encryption for any class that works with associative-array
 * rows (a datastore adapter, repository, mapper, etc.).
 *
 * Implement the two abstract-style hooks by declaring them on the using class:
 *
 *   protected function encryptionStrategy(): EncryptionStrategy { ... }
 *   protected function encryptedFields(): array { return ['token', 'secret']; }
 *
 * then call {@see encryptAttributes()} before persisting and
 * {@see decryptAttributes()} after loading.
 */
trait EncryptsFields
{
    private ?FieldEncrypter $fieldEncrypter = null;

    /**
     * The strategy used to encrypt/decrypt. Declare this on the using class.
     */
    abstract protected function encryptionStrategy(): EncryptionStrategy;

    /**
     * Field names to encrypt. Declare this on the using class.
     *
     * @return list<string>
     */
    abstract protected function encryptedFields(): array;

    /**
     * Encrypt the managed fields on an outgoing row.
     *
     * @param array<string, mixed> $attributes
     * @param string               $context AEAD base context (e.g. a row id).
     *
     * @return array<string, mixed>
     */
    protected function encryptAttributes(array $attributes, string $context = ''): array
    {
        return $this->fieldEncrypter()->encryptRow($attributes, $context);
    }

    /**
     * Decrypt the managed fields on an incoming row.
     *
     * @param array<string, mixed> $attributes
     * @param string               $context The same base context used to encrypt.
     *
     * @return array<string, mixed>
     */
    protected function decryptAttributes(array $attributes, string $context = ''): array
    {
        return $this->fieldEncrypter()->decryptRow($attributes, $context);
    }

    private function fieldEncrypter(): FieldEncrypter
    {
        if ($this->fieldEncrypter === null) {
            $this->fieldEncrypter = new FieldEncrypter(
                $this->encryptionStrategy(),
                $this->encryptedFields()
            );
        }

        return $this->fieldEncrypter;
    }
}
