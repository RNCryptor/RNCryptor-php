<?php
namespace Tests\RNCryptor;

use PHPUnit\Framework\TestCase;
use RNCryptor\RNCryptor\Cryptor;
use RNCryptor\RNCryptor\Encryptor;

class VectorBase extends TestCase
{
    /**
     * Base directory for the test vector files,
     * relative to __DIR__
     */
    const PARALLEL_VECTOR_DIR = '/../../../spec/vectors/CURRENT';
    const SUBPACKAGE_VECTOR_DIR = '/../../vendor/rncryptor/spec/vectors/CURRENT';

    public function testKdfVectorAllFieldsEmptyOrZero()
    {
        $vector = $this->getVectors('kdf')[0];

        $cryptor = new Cryptor;
        $key = $cryptor->generateKey(
            $this->prettyHexToBin($vector['salt_hex']),
            $vector['password'],
            $vector['version']
        );

        $this->assertEquals($this->prettyHexToBin($vector['key_hex']), $key);
    }

    public function testKdfVectorOneByte()
    {
        $vector = $this->getVectors('kdf')[1];

        $cryptor = new Cryptor;
        $key = $cryptor->generateKey(
            $this->prettyHexToBin($vector['salt_hex']),
            $vector['password'],
            $vector['version']
        );

        $this->assertEquals($this->prettyHexToBin($vector['key_hex']), $key);
    }

    public function testKdfVectorExactlyOneBlock()
    {
        $vector = $this->getVectors('kdf')[2];

        $cryptor = new Cryptor;
        $key = $cryptor->generateKey(
            $this->prettyHexToBin($vector['salt_hex']),
            $vector['password'],
            $vector['version']
        );

        $this->assertEquals($this->prettyHexToBin($vector['key_hex']), $key);
    }

    public function testKdfVectorMoreThanOneBlock()
    {
        $vector = $this->getVectors('kdf')[3];

        $cryptor = new Cryptor;
        $key = $cryptor->generateKey(
            $this->prettyHexToBin($vector['salt_hex']),
            $vector['password'],
            $vector['version']
        );

        $this->assertEquals($this->prettyHexToBin($vector['key_hex']), $key);
    }

    public function testKeyVectorAllFieldsEmptyOrZero()
    {
        $vector = $this->getVectors('key')[0];

        $encryptor = new Encryptor;
        $encryptedB64 = $encryptor->encryptWithArbitraryKeys(
            $this->prettyHexToBin($vector['plaintext_hex']),
            $this->prettyHexToBin($vector['enc_key_hex']),
            $this->prettyHexToBin($vector['hmac_key_hex']),
            $this->prettyHexToBin($vector['iv_hex']),
            $vector['version']
        );

        $this->assertEquals($vector['ciphertext_hex'], $this->binToPrettyHex(base64_decode($encryptedB64)));
    }

    public function testKeyVectorOneByte()
    {
        $vector = $this->getVectors('key')[1];

        $encryptor = new Encryptor;
        $encryptedB64 = $encryptor->encryptWithArbitraryKeys(
            $this->prettyHexToBin($vector['plaintext_hex']),
            $this->prettyHexToBin($vector['enc_key_hex']),
            $this->prettyHexToBin($vector['hmac_key_hex']),
            $this->prettyHexToBin($vector['iv_hex']),
            $vector['version']
        );

        $this->assertEquals($vector['ciphertext_hex'], $this->binToPrettyHex(base64_decode($encryptedB64)));
    }

    public function testKeyVectorExactlyOneBlock()
    {
        $vector = $this->getVectors('key')[2];

        $encryptor = new Encryptor;
        $encryptedB64 = $encryptor->encryptWithArbitraryKeys(
            $this->prettyHexToBin($vector['plaintext_hex']),
            $this->prettyHexToBin($vector['enc_key_hex']),
            $this->prettyHexToBin($vector['hmac_key_hex']),
            $this->prettyHexToBin($vector['iv_hex']),
            $vector['version']
        );

        $this->assertEquals($vector['ciphertext_hex'], $this->binToPrettyHex(base64_decode($encryptedB64)));
    }

    public function testKeyVectorMoreThanOneBlock()
    {
        $vector = $this->getVectors('key')[3];

        $encryptor = new Encryptor;
        $encryptedB64 = $encryptor->encryptWithArbitraryKeys(
            $this->prettyHexToBin($vector['plaintext_hex']),
            $this->prettyHexToBin($vector['enc_key_hex']),
            $this->prettyHexToBin($vector['hmac_key_hex']),
            $this->prettyHexToBin($vector['iv_hex']),
            $vector['version']
        );

        $this->assertEquals($vector['ciphertext_hex'], $this->binToPrettyHex(base64_decode($encryptedB64)));
    }

    public function testPasswordVectorAllFieldsEmptyOrZero()
    {
        $vector = $this->getVectors('password')[0];

        $encryptor = new Encryptor;
        $encryptedB64 = $encryptor->encryptWithArbitrarySalts(
            $this->prettyHexToBin($vector['plaintext_hex']),
            $vector['password'],
            $this->prettyHexToBin($vector['enc_salt_hex']),
            $this->prettyHexToBin($vector['hmac_salt_hex']),
            $this->prettyHexToBin($vector['iv_hex']),
            $vector['version']
        );

        $this->assertEquals($vector['ciphertext_hex'], $this->binToPrettyHex(base64_decode($encryptedB64)));
    }

    public function testPasswordVectorOneByte()
    {
        $vector = $this->getVectors('password')[1];

        $encryptor = new Encryptor;
        $encryptedB64 = $encryptor->encryptWithArbitrarySalts(
            $this->prettyHexToBin($vector['plaintext_hex']),
            $vector['password'],
            $this->prettyHexToBin($vector['enc_salt_hex']),
            $this->prettyHexToBin($vector['hmac_salt_hex']),
            $this->prettyHexToBin($vector['iv_hex']),
            $vector['version']
        );

        $this->assertEquals($vector['ciphertext_hex'], $this->binToPrettyHex(base64_decode($encryptedB64)));
    }

    public function testPasswordVectorExactlyOneBlock()
    {
        $vector = $this->getVectors('password')[2];

        $encryptor = new Encryptor;
        $encryptedB64 = $encryptor->encryptWithArbitrarySalts(
            $this->prettyHexToBin($vector['plaintext_hex']),
            $vector['password'],
            $this->prettyHexToBin($vector['enc_salt_hex']),
            $this->prettyHexToBin($vector['hmac_salt_hex']),
            $this->prettyHexToBin($vector['iv_hex']),
            $vector['version']
        );

        $this->assertEquals($vector['ciphertext_hex'], $this->binToPrettyHex(base64_decode($encryptedB64)));
    }

    public function testPasswordVectorMoreThanOneBlock()
    {
        $vector = $this->getVectors('password')[3];

        $encryptor = new Encryptor;
        $encryptedB64 = $encryptor->encryptWithArbitrarySalts(
            $this->prettyHexToBin($vector['plaintext_hex']),
            $vector['password'],
            $this->prettyHexToBin($vector['enc_salt_hex']),
            $this->prettyHexToBin($vector['hmac_salt_hex']),
            $this->prettyHexToBin($vector['iv_hex']),
            $vector['version']
        );

        $this->assertEquals($vector['ciphertext_hex'], $this->binToPrettyHex(base64_decode($encryptedB64)));
    }

    private function prettyHexToBin($data)
    {
        return hex2bin(preg_replace("/[^a-z0-9]/i", '', $data));
    }

    private function binToPrettyHex($data)
    {
        $hex = bin2hex($data);

        $prettyHex = '';
        foreach (str_split($hex, 8) as $index => $part) {
            $prettyHex .= ($index != 0 ? ' ' : '') . $part;
        }
        return $prettyHex;
    }

    private function getVectors($filename)
    {
        $absolutePath = __DIR__ . '/' . self::PARALLEL_VECTOR_DIR . '/' . $filename;
        if (!file_exists($absolutePath)) {
            $absolutePath = __DIR__ . '/' . self::SUBPACKAGE_VECTOR_DIR . '/' . $filename;
            if (!file_exists($absolutePath)) {
                throw new \Exception('No such file: ' . $absolutePath);
            }
        }

        $index = -1;
        $tests = array();
        $fd = fopen($absolutePath, 'r');
        while (!feof($fd)) {
            $line = trim(fgets($fd));
    
            if (preg_match("/^\s*(\w+)\s*\:\s*(.*)/", $line, $match)) {
                $key = strtolower($match[1]);
                $value = trim($match[2]);
    
                if ($key == 'title') {
                    $index++;
                }
    
                $tests[$index][$key] = $value;
            }
        }
        fclose($fd);
    
        return $tests;
    }
}
