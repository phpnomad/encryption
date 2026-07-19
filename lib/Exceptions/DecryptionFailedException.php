<?php

namespace PHPNomad\Encryption\Exceptions;

/**
 * Thrown when a ciphertext cannot be authenticated or decrypted — a wrong key,
 * a mismatched AEAD context, or tampered data.
 */
class DecryptionFailedException extends EncryptionException
{
}
