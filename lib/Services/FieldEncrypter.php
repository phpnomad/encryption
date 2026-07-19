<?php

namespace PHPNomad\Encryption\Services;

use PHPNomad\Encryption\Interfaces\EncryptionStrategy;
use PHPNomad\Encryption\ValueObjects\EncryptedValue;

/**
 * Transparently encrypts and decrypts a fixed set of fields on an associative
 * array — encrypt-on-write, decrypt-on-read — without any storage-layer
 * coupling. Wire it into a datastore, an ORM hook, an API serializer, or call
 * it by hand; it only ever touches plain PHP arrays.
 *
 * Each field is encrypted independently and stored as a compact self-describing
 * string ({@see EncryptedValue::toString()}), so a single text column per field
 * is all the schema you need.
 *
 * AEAD binding: every field is bound to associated data derived from a base
 * context and the field name (`"{context}:{field}"`, or just the field name
 * when no context is given). That pins each ciphertext to its column — moving a
 * value into a different field, or lifting a whole row's context, breaks
 * decryption instead of silently succeeding.
 */
final class FieldEncrypter
{
    private EncryptionStrategy $strategy;

    /** @var list<string> */
    private array $fields;

    /**
     * @param EncryptionStrategy $strategy The cipher to use.
     * @param list<string>       $fields   Field names to encrypt/decrypt.
     */
    public function __construct(EncryptionStrategy $strategy, array $fields)
    {
        $this->strategy = $strategy;
        $this->fields = array_values($fields);
    }

    /**
     * Return a copy of $row with every managed field encrypted in place.
     *
     * Null values and already-encrypted values are left untouched, so the call
     * is idempotent and safe to run on partial updates. Absent fields are skipped.
     *
     * @param array<string, mixed> $row
     * @param string               $context Base associated data (e.g. a row/tenant id).
     *
     * @return array<string, mixed>
     */
    public function encryptRow(array $row, string $context = ''): array
    {
        foreach ($this->fields as $field) {
            if (!array_key_exists($field, $row) || $row[$field] === null) {
                continue;
            }

            $value = (string) $row[$field];

            if (EncryptedValue::isEncryptedString($value)) {
                continue;
            }

            $row[$field] = $this->strategy
                ->encrypt($value, $this->contextFor($field, $context))
                ->toString();
        }

        return $row;
    }

    /**
     * Return a copy of $row with every managed field decrypted in place.
     *
     * Null values and values that are not encrypted strings are left untouched.
     * Absent fields are skipped.
     *
     * @param array<string, mixed> $row
     * @param string               $context The same base context used to encrypt.
     *
     * @return array<string, mixed>
     */
    public function decryptRow(array $row, string $context = ''): array
    {
        foreach ($this->fields as $field) {
            if (!array_key_exists($field, $row) || $row[$field] === null) {
                continue;
            }

            $value = (string) $row[$field];

            if (!EncryptedValue::isEncryptedString($value)) {
                continue;
            }

            $row[$field] = $this->strategy->decrypt(
                EncryptedValue::fromString($value),
                $this->contextFor($field, $context)
            );
        }

        return $row;
    }

    private function contextFor(string $field, string $context): string
    {
        return $context === '' ? $field : $context . ':' . $field;
    }
}
