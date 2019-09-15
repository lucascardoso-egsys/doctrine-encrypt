<?php

namespace DoctrineEncrypt\Tests\Tool;

use DoctrineEncrypt\Encryptors\EncryptorInterface;

class Rot13Encryptor implements EncryptorInterface
{
    /**
     * Must accept data and return encrypted data.
     */
    public function encrypt($data): string
    {
        return str_rot13($data);
    }

    /**
     * Must accept data and return decrypted data.
     */
    public function decrypt($data): string
    {
        return str_rot13($data);
    }
}
