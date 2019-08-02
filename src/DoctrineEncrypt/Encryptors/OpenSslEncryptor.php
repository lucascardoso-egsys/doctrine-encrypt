<?php

namespace DoctrineEncrypt\Encryptors;

/**
 * Class for OpenSSL encryption
 *
 * @author Lucas Saraiva <lucassaraiva5@hotmail.com>
 */
class OpenSslEncryptor implements EncryptorInterface
{
    const RSA_ALGORITHM_KEY_TYPE = OPENSSL_KEYTYPE_RSA;
    const RSA_ALGORITHM_SIGN = OPENSSL_ALGO_SHA256;

    /**
     * Secret key for aes algorythm
     * @var string
     */
    private $secretKey;

    private $privateKey;

    private $publicKey;

    private $passPhrase;

    /**
     * Initialization of encryptor
     * @param string $key
     */
    public function __construct($key)
    {
        $this->secretKey = $key;
        $this->privateKey = $key["private"];
        $this->publicKey = $key["public"];
        $this->passPhrase = $key["pass"];
        $pub_id = openssl_get_publickey($this->publicKey);
        $this->key_len = openssl_pkey_get_details($pub_id)['bits'];
    }

    public function encrypt($data)
    {
        $encrypted = '';
        $part_len = $this->key_len / 8 - 11;
        $parts = str_split($data, $part_len);

        foreach ($parts as $part) {
            $encrypted_temp = '';
            openssl_public_encrypt($part, $encrypted_temp, $this->publicKey);
            $encrypted .= $encrypted_temp;
        }

        return base64_encode($encrypted);
    }

    public function decrypt($encrypted)
    {
        $decrypted = "";
        $part_len = $this->key_len / 8;
        $base64_decoded = base64_decode($encrypted);
        $parts = str_split($base64_decoded, $part_len);
        $privateKey = openssl_get_privatekey($this->privateKey,$this->passPhrase);

        foreach ($parts as $part) {
            $decrypted_temp = '';
            openssl_private_decrypt($part, $decrypted_temp, $privateKey);
            $decrypted .= $decrypted_temp;
        }

        return $decrypted;
    }
}
