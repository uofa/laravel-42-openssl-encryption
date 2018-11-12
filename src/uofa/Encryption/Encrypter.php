<?php

namespace Uofa\Encryption;

use Illuminate\Encryption\DecryptException;
use Illuminate\Encryption\Encrypter as BaseEncrypter;

class Encrypter extends BaseEncrypter
{
    /**
     * Encrypter constructor.
     *
     * @param string $key
     * @param string $cipher
     */
    public function __construct($key, $cipher = 'AES-256-CBC')
    {
        parent::__construct($key);

        $this->cipher = $cipher;

        if (! static::supported($this->key, $this->cipher)) {
            throw new \RuntimeException('The only supported ciphers are AES-128-CBC and AES-256-CBC.');
        }
    }

     /**
     * Check if the given key and cipher is valid.
     *
     * @param string $key
     * @param string $cipher
     *
     * @return bool
     */
    public static function supported($key, $cipher)
    {
        $length = mb_strlen($key, '8bit');
        return ($cipher === 'AES-128-CBC' && $length === 16) ||
            ($cipher === 'AES-256-CBC' && $length === 32);
    }
    
    /**
     * Encrypt and serialize given value
     *
     * @param $value
     * @param bool $serialize
     *
     * @return string
     */
    public function encrypt($value, $serialize = true)
    {
        $iv = random_bytes(16);
        // Encrypt value using OpenSSL. If value is not valid throw exception.
        $value = \openssl_encrypt(
            $serialize ? serialize($value) : $value,
            $this->cipher,
            $this->key,
            0,
            $iv
        );
        if ($value === false) {
            throw new \RuntimeException('Could not encrypt the data.');
        }
        // Once value is ecrpted create MAC so we could check its authenticity.
        $mac = $this->hash($iv = base64_encode($iv), $value);
        $json = json_encode(compact('iv', 'value', 'mac'));
        if (! is_string($json)) {
            throw new \RuntimeException('Could not encrypt the data.');
        }
        return base64_encode($json);
    }

    /**
     * Encrypt a string without using serialization.
     *
     * @param string $value
     * @return string
     */
    public function encryptString($value)
    {
        return $this->encrypt($value, false);
    }
    
    /**
     * Decrypt given payload.
     *
     * @param $payload
     * @param bool $unserialize
     * @return mixed|string
     */
    public function decrypt($payload, $unserialize = true)
    {
        $payload = $this->getJsonPayload($payload);
        $iv = base64_decode($payload['iv']);
        // Check if we are able to successfully decrypt serialized value,
        // if we can decrypt it then we unserialize it and return, if no
        // then we throw an exception.
        $decrypted = \openssl_decrypt($payload['value'], $this->cipher, $this->key, 0, $iv);
        if ($decrypted === false) {
            throw new DecryptException('Could not decrypt the data.');
        }
        return $unserialize ? unserialize($decrypted) : $decrypted;
    }

    /**
     * Decrypt the given string without unserialization.
     *
     * @param  string  $payload
     * @return string
     */
    public function decryptString($payload)
    {
        return $this->decrypt($payload, false);
    }

    /**
     * Create a MAC for the given value.
     *
     * @param string $iv
     * @param mixed  $value
     * @return string
     */
    protected function hash($iv, $value)
    {
        return hash_hmac('sha256', $iv.$value, $this->key);
    }

    /**
     * Check if json payload is correct and return it.
     *
     * @param $payload
     * @return mixed
     */
    protected function getJsonPayload($payload)
    {
        $payload = json_decode(base64_decode($payload), true);
        // If payload is returned as not valid or ir does not have correct keys
        // we won't be able to decrypt it.
        if (! $this->validPayload($payload)) {
            throw new DecryptException('The payload is invalid.');
        }
        if (! $this->validMac($payload)) {
            throw new DecryptException('The MAC is invalid.');
        }
        return $payload;
    }

    /**
     * Check if the encryption payload is correct.
     *
     * @param mixed $payload
     * @return bool
     */
    protected function validPayload($payload)
    {
        return is_array($payload) && isset($payload['iv'], $payload['value'], $payload['mac']);
    }

    /**
     * Check if the MAC for the given payload is correct.
     *
     * @param array $payload
     * @return bool
     */
    protected function validMac(array $payload)
    {
        $calculated = $this->calculateMac($payload, $bytes = random_bytes(16));
        return hash_equals(
            hash_hmac('sha256', $payload['mac'], $bytes, true),
            $calculated
        );
    }

    /**
     * Calculate the hash of the given payload.
     *
     * @param array  $payload
     * @param string $bytes
     * @return string
     */
    protected function calculateMac($payload, $bytes)
    {
        return hash_hmac('sha256', $this->hash($payload['iv'], $payload['value']), $bytes, true);
    }

    /**
     * Get the encryption key.
     *
     * @return string
     */
    public function getKey()
    {
        return $this->key;
    }

    /**
     * Set the encryption key.
     *
     * @param string $key
     * @return void
     */
    public function setKey($key)
    {
        $this->key = $key;
    }

    /**
     * Set the encryption cipher.
     *
     * @param string $cipher
     * @return void
     */
    public function setCipher($cipher)
    {
        $this->cipher = $cipher;
    }
}
