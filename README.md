# phpnomad/encryption

Encryption **contracts** and framework-agnostic **field-level encryption** for
PHPNomad — bring your own cipher via an integration package. This package holds
only interfaces, value objects, key providers, and the field/attribute helpers.
It has no cipher dependency (no `ext-sodium`, no framework, no ORM) — just PHP.

The default cipher lives in a separate integration:
**[`phpnomad/sodium-integration`](https://github.com/phpnomad/sodium-integration)**
(libsodium XChaCha20-Poly1305 AEAD).

- **Contract-first.** `EncryptionStrategy` and `KeyProvider` are the seams; swap
  ciphers or key sources without touching call sites.
- **Context binding.** The contract requires ciphertext to be bound to a caller
  context (associated data), so a value copied elsewhere won't decrypt.
- **Key rotation built in.** Keys are versioned; encrypt with the current
  version, decrypt against whatever version sealed the data.
- **Field-level helper.** `FieldEncrypter` / `EncryptsFields` do
  encrypt-on-write / decrypt-on-read for marked fields of a plain array — wire it
  into any storage layer, over any strategy.

## Requirements

- PHP >= 8.2
- A cipher implementation — e.g. `phpnomad/sodium-integration`.

## Install

```bash
composer require phpnomad/encryption phpnomad/sodium-integration
```

`phpnomad/encryption` gives you the contracts and helpers;
`phpnomad/sodium-integration` gives you the `SodiumEncryptionStrategy` to wire in.

## Quickstart

```php
use PHPNomad\Encryption\Providers\ArrayKeyProvider;
use PHPNomad\Encryption\ValueObjects\EncryptedValue;
use PHPNomad\Sodium\EncryptionIntegration\Strategies\SodiumEncryptionStrategy;

// A key ring holding one 32-byte key at version 1.
$keys = new ArrayKeyProvider([1 => sodium_crypto_aead_xchacha20poly1305_ietf_keygen()]);

// The cipher comes from the integration package; everything else is this one.
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
use PHPNomad\Sodium\EncryptionIntegration\Strategies\SodiumEncryptionStrategy;

// Reads a base64-encoded 32-byte key from APP_MASTER_KEY (file fallback optional).
$keys = new Base64EnvKeyProvider('APP_MASTER_KEY', __DIR__ . '/.master_key');
$encryption = new SodiumEncryptionStrategy($keys);
```

## Associated data (AEAD context)

The second argument to `encrypt()`/`decrypt()` is **associated data**:
authenticated but not encrypted. Use it to bind a ciphertext to where it lives.
The *same* context must be supplied to decrypt.

```php
$sealed = $encryption->encrypt($token, "tenant:42:column:access_token");

$encryption->decrypt($sealed, "tenant:42:column:access_token"); // ok
$encryption->decrypt($sealed, "tenant:99:column:access_token"); // throws DecryptionFailedException
```

This turns an encrypted-value swap between rows or columns from a silent success
into a hard failure.

## Field-level encryption

`FieldEncrypter` transparently encrypts a fixed set of fields on an associative
array and decrypts them on the way back — no storage coupling, and cipher-agnostic
(pass any `EncryptionStrategy`). Each field is bound to its own AEAD context
(`"{context}:{field}"`), so values can't be swapped between columns.

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

`encryptRow()` is idempotent (already-encrypted and `null` values are left
alone), so it's safe on partial updates.

Prefer a trait? `EncryptsFields` wires the same behavior into a datastore adapter
or repository:

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

Keys are addressed by version. Keep every version still referenced by stored
ciphertext; point the ring's current version at the newest key.

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

To fully migrate, decrypt each stored value and re-encrypt it (the new
`EncryptedValue` carries `keyVersion = 2`), then retire the old key once nothing
references it. Multiple keys can also live behind separate providers via
`KeyRing` (e.g. one `Base64EnvKeyProvider` per env var).

## Writing a cipher integration

Implement `Interfaces\EncryptionStrategy` and return an `EncryptedValue`:

```php
use PHPNomad\Encryption\Interfaces\EncryptionStrategy;
use PHPNomad\Encryption\ValueObjects\EncryptedValue;

final class MyCipherStrategy implements EncryptionStrategy
{
    public function encrypt(string $plaintext, string $context = ''): EncryptedValue { /* ... */ }
    public function decrypt(EncryptedValue $value, string $context = ''): string { /* ... */ }
}
```

The contract requires that decryption fail (throw `DecryptionFailedException`) on
a wrong key, a mismatched `$context`, or tampered bytes, and that it decrypt
against the key version recorded on the value. See `phpnomad/sodium-integration`
for the reference implementation.

## API at a glance

| Type | Role |
| --- | --- |
| `Interfaces\EncryptionStrategy` | `encrypt(string, context): EncryptedValue` / `decrypt(EncryptedValue, context): string` |
| `Interfaces\KeyProvider` | `getKey(version): string` / `currentVersion(): int` |
| `ValueObjects\EncryptedValue` | ciphertext + nonce + keyVersion + cipher; `toArray`/`fromArray`, `toString`/`fromString` |
| `Providers\ArrayKeyProvider` | in-memory versioned key ring |
| `Providers\Base64EnvKeyProvider` | base64 key from env var / file |
| `Providers\KeyRing` | compose per-version providers |
| `Services\FieldEncrypter` | encrypt/decrypt marked array fields |
| `Traits\EncryptsFields` | field encryption mixin for repositories/adapters |
| `Exceptions\*` | `EncryptionException`, `DecryptionFailedException`, `KeyNotFoundException` |
| *cipher strategy* | provided by an integration, e.g. `phpnomad/sodium-integration` |

## Testing

```bash
composer install
composer test
```

The contract suite has no cipher dependency — it exercises the strategy contract
against a small in-package reversible fake. The real libsodium cipher is tested
in `phpnomad/sodium-integration`.

## License

MIT © Novatorius / Alex Standiford
