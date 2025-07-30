<?php

namespace MordenSecurity\Utils;

if (!defined('ABSPATH')) {
    exit;
}

class Encryption
{
    private static string $method = 'AES-256-CBC';
    private static string $keyOption = 'ms_encryption_key';

    public static function encrypt(string $data): string
    {
        if (empty($data)) {
            return '';
        }

        $key = self::getEncryptionKey();
        $iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length(self::$method));

        $encrypted = openssl_encrypt($data, self::$method, $key, 0, $iv);

        if ($encrypted === false) {
            return '';
        }

        return base64_encode($iv . $encrypted);
    }

    public static function decrypt(string $encryptedData): string
    {
        if (empty($encryptedData)) {
            return '';
        }

        $data = base64_decode($encryptedData);

        if ($data === false) {
            return '';
        }

        $key = self::getEncryptionKey();
        $ivLength = openssl_cipher_iv_length(self::$method);

        $iv = substr($data, 0, $ivLength);
        $encrypted = substr($data, $ivLength);

        $decrypted = openssl_decrypt($encrypted, self::$method, $key, 0, $iv);

        return $decrypted !== false ? $decrypted : '';
    }

    public static function hash(string $data, string $salt = ''): string
    {
        if (empty($salt)) {
            $salt = self::getHashSalt();
        }

        return hash('sha256', $data . $salt);
    }

    public static function generateSecureToken(int $length = 32): string
    {
        $bytes = openssl_random_pseudo_bytes($length);
        return bin2hex($bytes);
    }

    public static function verifyHash(string $data, string $hash, string $salt = ''): bool
    {
        return hash_equals($hash, self::hash($data, $salt));
    }

    public static function encryptSensitiveData(array $data): string
    {
        $json = json_encode($data);

        if ($json === false) {
            return '';
        }

        return self::encrypt($json);
    }

    public static function decryptSensitiveData(string $encryptedData): array
    {
        $json = self::decrypt($encryptedData);

        if (empty($json)) {
            return [];
        }

        $data = json_decode($json, true);

        return is_array($data) ? $data : [];
    }

    private static function getEncryptionKey(): string
    {
        $key = get_option(self::$keyOption);

        if (empty($key)) {
            $key = self::generateEncryptionKey();
            update_option(self::$keyOption, $key);
        }

        return $key;
    }

    private static function generateEncryptionKey(): string
    {
        $key = openssl_random_pseudo_bytes(32);
        return base64_encode($key);
    }

    private static function getHashSalt(): string
    {
        if (defined('AUTH_SALT')) {
            return AUTH_SALT;
        }

        return 'morden-security-default-salt';
    }
}
