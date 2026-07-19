# phpnomad/encryption

Encryption **contracts** for PHPNomad — bring your own cipher via an integration
package. This package holds only the strategy and key-provider interfaces, the
immutable encrypted-value model, the key providers, and the exception types. It
makes **no assumption about how you store or transport an encrypted value** — no
serialization format, no column shape. It has no cipher dependency (no
`ext-sodium`, no framework, no ORM) — just PHP.

The default cipher lives in a separate integration:
**[`phpnomad/sodium-integration`](https://github.com/phpnomad/sodium-integration)**
(libsodium XChaCha20-Poly1305 AEAD).

- **Contract-first.** `EncryptionStrategy` and `KeyProvider` are the seams; swap
  ciphers or key sources without touching call sites.
- **Context binding.** The contract requires ciphertext to be bound to a caller
  context (associated data), so a value copied elsewhere won't decrypt.
- **Key rotation built in.** Keys are versioned; encrypt with the current
  version, decrypt against whatever version sealed the data.
- **Storage-agnostic.** `EncryptedValue` is pure data — ciphertext, nonce, key
  version, and an opaque cipher tag. How you persist it is entirely yours.

## Requirements

- PHP >= 8.2
- A cipher implementation — e.g. `phpnomad/sodium-integration`.

## Install

```bash
composer require phpnomad/encryption phpnomad/sodium-integration
```

`phpnomad/encryption` gives you the contracts; `phpnomad/sodium-integration`
gives you the `SodiumEncryptionStrategy` to wire in.

## Quickstart

```php
use PHPNomad\Encryption\Providers\ArrayKeyProvider;
use PHPNomad\Encryption\Models\EncryptedValue;
use PHPNomad\Sodium\EncryptionIntegration\Strategies\SodiumEncryptionStrategy;

// A key ring holding one 32-byte key at version 1.
$keys = new ArrayKeyProvider([1 => sodium_crypto_aead_xchacha20poly1305_ietf_keygen()]);

// The cipher comes from the integration package; everything else is this one.
$encryption = new SodiumEncryptionStrategy($keys);

$sealed = $encryption->encrypt('sk-live-super-secret');

// Persist it however your storage layer prefers — the value is pure data, so the
// shape is yours. For example, spread across columns (base64 for text columns):
$row = [
    'ciphertext'  => base64_encode($sealed->getCiphertext()),
    'nonce'       => base64_encode($sealed->getNonce()),
    'key_version' => $sealed->getKeyVersion(),
    'cipher'      => $sealed->getCipher(),
];

// Later — rebuild the value from your stored fields and decrypt:
$restored = new EncryptedValue(
    base64_decode($row['ciphertext']),
    base64_decode($row['nonce']),
    (int) $row['key_version'],
    $row['cipher'],
);

$plaintext = $encryption->decrypt($restored);
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
into a hard failure. If you encrypt several fields on one record, give each its
own context (e.g. `"record:{id}:{field}"`) so ciphertexts can't be swapped
between columns.

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

Implement `Interfaces\EncryptionStrategy` and return an `EncryptedValue`, stamping
your own opaque cipher discriminator so decrypt-time can recognize it:

```php
use PHPNomad\Encryption\Interfaces\EncryptionStrategy;
use PHPNomad\Encryption\Models\EncryptedValue;

final class MyCipherStrategy implements EncryptionStrategy
{
    public const CIPHER = 'my-cipher-v1';

    public function encrypt(string $plaintext, string $context = ''): EncryptedValue { /* ...return new EncryptedValue($ct, $nonce, $version, self::CIPHER) */ }
    public function decrypt(EncryptedValue $value, string $context = ''): string { /* ... */ }
}
```

The contract requires that decryption fail (throw `DecryptionFailedException`) on
a wrong key, a mismatched `$context`, or tampered bytes, and that it decrypt
against the key version recorded on the value. The `cipher` discriminator is
owned by the strategy, not this package — the contract names no ciphers. See
`phpnomad/sodium-integration` for the reference implementation.

## API at a glance

| Type | Role |
| --- | --- |
| `Interfaces\EncryptionStrategy` | `encrypt(string, context): EncryptedValue` / `decrypt(EncryptedValue, context): string` |
| `Interfaces\KeyProvider` | `getKey(version): string` / `currentVersion(): int` |
| `Models\EncryptedValue` | immutable data: ciphertext + nonce + keyVersion + opaque cipher tag; getters only |
| `Providers\ArrayKeyProvider` | in-memory versioned key ring |
| `Providers\Base64EnvKeyProvider` | base64 key from env var / file |
| `Providers\KeyRing` | compose per-version providers |
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
