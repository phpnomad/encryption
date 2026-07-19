# phpnomad/encryption

Interface-driven [libsodium](https://www.php.net/manual/en/book.sodium.php) encryption primitives for PHP: authenticated encryption (AEAD), versioned keys with rotation, and framework-agnostic field-level encryption. No framework, ORM, or datastore dependency — just PHP and `ext-sodium`.

- **Authenticated by default.** Every ciphertext is sealed with XChaCha20-Poly1305 AEAD, so tampering is detected on decrypt.
- **Context binding.** Pin a ciphertext to the row, column, or tenant it belongs to. A value copied elsewhere won't decrypt.
- **Key rotation built in.** Keys are versioned; encrypt with the current version, decrypt against whatever version sealed the data.
- **Field-level helper.** Encrypt-on-write / decrypt-on-read for marked fields of a plain array — wire it into any storage layer.
- **Migration-friendly.** Can read legacy `sodium_crypto_secretbox` data while you move to AEAD.

## Requirements

- PHP >= 8.2
- `ext-sodium` (bundled with PHP 7.2+)

## Install

```bash
composer require phpnomad/encryption
```

## Quickstart

```php
use PHPNomad\Encryption\Providers\ArrayKeyProvider;
use PHPNomad\Encryption\Strategies\SodiumEncryptionStrategy;
use PHPNomad\Encryption\ValueObjects\EncryptedValue;

// A key ring holding one 32-byte key at version 1.
$keys = new ArrayKeyProvider([1 => sodium_crypto_aead_xchacha20poly1305_ietf_keygen()]);

$encryption = new SodiumEncryptionStrategy($keys);

$sealed = $encryption->encrypt('sk-live-super-secret');

// Store it. Either as a compact self-describing string...
$column = $sealed->toString();              // "enc:1:xchacha20poly1305_ietf:1:<nonce>:<ciphertext>"
// ...or spread across dedicated columns.
$row = $sealed->toArray();                  // ['ciphertext' => ..., 'nonce' => ..., 'keyVersion' => 1, 'cipher' => ...]

// Later:
$plaintext = $encryption->decrypt(EncryptedValue::fromString($column));
// => "sk-live-super-secret"
```

Generate a base64 key for your environment:

```bash
php -r 'echo base64_encode(sodium_crypto_aead_xchacha20poly1305_ietf_keygen()), "\n";'
```

### Loading the key from the environment

```php
use PHPNomad\Encryption\Providers\Base64EnvKeyProvider;

// Reads a base64-encoded 32-byte key from APP_MASTER_KEY (file fallback optional).
$keys = new Base64EnvKeyProvider('APP_MASTER_KEY', __DIR__ . '/.master_key');
$encryption = new SodiumEncryptionStrategy($keys);
```

## Associated data (AEAD context)

The second argument to `encrypt()`/`decrypt()` is **associated data**: authenticated but not encrypted. Use it to bind a ciphertext to where it lives. The *same* context must be supplied to decrypt.

```php
$sealed = $encryption->encrypt($token, "tenant:42:column:access_token");

$encryption->decrypt($sealed, "tenant:42:column:access_token"); // ok
$encryption->decrypt($sealed, "tenant:99:column:access_token"); // throws DecryptionFailedException
```

This turns an encrypted-value swap between rows or columns from a silent success into a hard failure.

## Field-level encryption

`FieldEncrypter` transparently encrypts a fixed set of fields on an associative array and decrypts them on the way back — no storage coupling. Each field is bound to its own AEAD context (`"{context}:{field}"`), so values can't be swapped between columns.

```php
use PHPNomad\Encryption\Services\FieldEncrypter;

$fields = new FieldEncrypter($encryption, ['access_token', 'refresh_token']);

// On write:
$row = $fields->encryptRow([
    'id'            => 5,
    'access_token'  => 'at-123',
    'refresh_token' => 'rt-456',
    'label'         => 'GitHub',       // untouched
], context: "connection:5");

// On read:
$row = $fields->decryptRow($row, context: "connection:5");
```

`encryptRow()` is idempotent (already-encrypted and `null` values are left alone), so it's safe on partial updates.

Prefer a trait? `EncryptsFields` wires the same behavior into a datastore adapter or repository:

```php
use PHPNomad\Encryption\Interfaces\EncryptionStrategy;
use PHPNomad\Encryption\Traits\EncryptsFields;

final class TokenRepository
{
    use EncryptsFields;

    public function __construct(private EncryptionStrategy $encryption) {}

    protected function encryptionStrategy(): EncryptionStrategy { return $this->encryption; }
    protected function encryptedFields(): array { return ['access_token', 'refresh_token']; }

    public function save(array $attributes): void
    {
        $attributes = $this->encryptAttributes($attributes, context: 'connection:' . $attributes['id']);
        // ...persist $attributes...
    }
}
```

## Key rotation

Keys are addressed by version. Keep every version still referenced by stored ciphertext; point the ring's current version at the newest key.

```php
// v1 was current when old values were sealed. Now add v2 and make it current.
$keys = new ArrayKeyProvider([
    1 => $oldKey,   // retained so old ciphertext still decrypts
    2 => $newKey,
], currentVersion: 2);

$encryption = new SodiumEncryptionStrategy($keys);

$encryption->encrypt('x');        // sealed under v2
$encryption->decrypt($oldValue);  // still decrypts against v1
```

To fully migrate, decrypt each stored value and re-encrypt it (the new `EncryptedValue` carries `keyVersion = 2`), then retire the old key once nothing references it. Multiple keys can also live behind separate providers via `KeyRing` (e.g. one `Base64EnvKeyProvider` per env var).

## Reading legacy `secretbox` data

If you're adopting this library over data previously encrypted with `sodium_crypto_secretbox`, enable the fallback so unmarked values are tried as AEAD first and then as secretbox:

```php
$encryption = new SodiumEncryptionStrategy($keys, allowLegacySecretboxFallback: true);
```

New writes are always AEAD; old secretbox values keep decrypting until you re-encrypt them. A standalone `LegacySecretboxEncryptionStrategy` is also provided for read-only or explicit secretbox handling.

## Security notes

- **XChaCha20-Poly1305** is used because its 24-byte nonce is large enough to pick at random per message without collision worries — no nonce counter to persist. Keys are 32 bytes.
- Keys are wiped from memory with `sodium_memzero` after each operation.
- Decryption failure (wrong key, wrong context, or tampering) always raises `DecryptionFailedException` — never a partial or forged plaintext.
- Associated data is authenticated, **not** encrypted. Don't put secrets in the context.
- This library encrypts values; it does **not** manage where your keys come from or how they're stored. Keep keys out of source control (environment variables, a secrets manager, or a KMS).

## API at a glance

| Type | Role |
| --- | --- |
| `Interfaces\EncryptionStrategy` | `encrypt(string, context): EncryptedValue` / `decrypt(EncryptedValue, context): string` |
| `Interfaces\KeyProvider` | `getKey(version): string` / `currentVersion(): int` |
| `ValueObjects\EncryptedValue` | ciphertext + nonce + keyVersion + cipher; `toArray`/`fromArray`, `toString`/`fromString` |
| `Strategies\SodiumEncryptionStrategy` | XChaCha20-Poly1305 AEAD (default), optional secretbox fallback |
| `Strategies\LegacySecretboxEncryptionStrategy` | read/write `sodium_crypto_secretbox` |
| `Providers\ArrayKeyProvider` | in-memory versioned key ring |
| `Providers\Base64EnvKeyProvider` | base64 key from env var / file |
| `Providers\KeyRing` | compose per-version providers |
| `Services\FieldEncrypter` | encrypt/decrypt marked array fields |
| `Traits\EncryptsFields` | field encryption mixin for repositories/adapters |

## Testing

```bash
composer install
composer test
```

## License

MIT © Novatorius / Alex Standiford
