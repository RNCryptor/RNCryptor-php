<?php
namespace RNCryptor;

class VectorBase extends \PHPUnit_Framework_TestCase {

	/**
	 * Base directory for the test vector files,
	 * relative to __DIR__
	 */
	const PARALLEL_VECTOR_DIR = '/../../../spec/vectors/CURRENT';
	const SUBPACKAGE_VECTOR_DIR = '/../../vendor/rncryptor/spec/vectors/CURRENT';

	public function testKdfVectorAllFieldsEmptyOrZero() {

		$vector = $this->_getVectors('kdf')[0];

        $cryptor = new Cryptor();
        $key = $cryptor->generateKey(
            $this->_prettyHexToBin($vector['salt_hex']),
            $vector['password'],
            $vector['version']
        );

        $this->assertEquals($this->_prettyHexToBin($vector['key_hex']), $key);
	}

    public function testKdfVectorOneByte() {

        $vector = $this->_getVectors('kdf')[1];

        $cryptor = new Cryptor();
        $key = $cryptor->generateKey(
            $this->_prettyHexToBin($vector['salt_hex']),
            $vector['password'],
            $vector['version']
        );

        $this->assertEquals($this->_prettyHexToBin($vector['key_hex']), $key);
    }

    public function testKdfVectorExactlyOneBlock() {

        $vector = $this->_getVectors('kdf')[2];

        $cryptor = new Cryptor();
        $key = $cryptor->generateKey(
            $this->_prettyHexToBin($vector['salt_hex']),
            $vector['password'],
            $vector['version']
        );

        $this->assertEquals($this->_prettyHexToBin($vector['key_hex']), $key);
    }

    public function testKdfVectorMoreThanOneBlock() {

        $vector = $this->_getVectors('kdf')[3];

        $cryptor = new Cryptor();
        $key = $cryptor->generateKey(
            $this->_prettyHexToBin($vector['salt_hex']),
            $vector['password'],
            $vector['version']
        );

        $this->assertEquals($this->_prettyHexToBin($vector['key_hex']), $key);
    }

    public function testKeyVectorAllFieldsEmptyOrZero() {

		$vector = $this->_getVectors('key')[0];

        $encryptor = new Encryptor();
        $encryptedB64 = $encryptor->encryptWithArbitraryKeys(
            $this->_prettyHexToBin($vector['plaintext_hex']),
            $this->_prettyHexToBin($vector['enc_key_hex']),
            $this->_prettyHexToBin($vector['hmac_key_hex']),
            $this->_prettyHexToBin($vector['iv_hex']),
            $vector['version']
        );

        $this->assertEquals($vector['ciphertext_hex'], $this->_binToPrettyHex(base64_decode($encryptedB64)));
	}

    public function testKeyVectorOneByte() {

        $vector = $this->_getVectors('key')[1];

        $encryptor = new Encryptor();
        $encryptedB64 = $encryptor->encryptWithArbitraryKeys(
            $this->_prettyHexToBin($vector['plaintext_hex']),
            $this->_prettyHexToBin($vector['enc_key_hex']),
            $this->_prettyHexToBin($vector['hmac_key_hex']),
            $this->_prettyHexToBin($vector['iv_hex']),
            $vector['version']
        );

        $this->assertEquals($vector['ciphertext_hex'], $this->_binToPrettyHex(base64_decode($encryptedB64)));
    }

    public function testKeyVectorExactlyOneBlock() {

        $vector = $this->_getVectors('key')[2];

        $encryptor = new Encryptor();
        $encryptedB64 = $encryptor->encryptWithArbitraryKeys(
            $this->_prettyHexToBin($vector['plaintext_hex']),
            $this->_prettyHexToBin($vector['enc_key_hex']),
            $this->_prettyHexToBin($vector['hmac_key_hex']),
            $this->_prettyHexToBin($vector['iv_hex']),
            $vector['version']
        );

        $this->assertEquals($vector['ciphertext_hex'], $this->_binToPrettyHex(base64_decode($encryptedB64)));
    }

    public function testKeyVectorMoreThanOneBlock() {

        $vector = $this->_getVectors('key')[3];

        $encryptor = new Encryptor();
        $encryptedB64 = $encryptor->encryptWithArbitraryKeys(
            $this->_prettyHexToBin($vector['plaintext_hex']),
            $this->_prettyHexToBin($vector['enc_key_hex']),
            $this->_prettyHexToBin($vector['hmac_key_hex']),
            $this->_prettyHexToBin($vector['iv_hex']),
            $vector['version']
        );

        $this->assertEquals($vector['ciphertext_hex'], $this->_binToPrettyHex(base64_decode($encryptedB64)));
    }

    public function testPasswordVectorAllFieldsEmptyOrZero() {

		$vector = $this->_getVectors('password')[0];

        $encryptor = new Encryptor();
        $encryptedB64 = $encryptor->encryptWithArbitrarySalts(
            $this->_prettyHexToBin($vector['plaintext_hex']),
            $vector['password'],
            $this->_prettyHexToBin($vector['enc_salt_hex']),
            $this->_prettyHexToBin($vector['hmac_salt_hex']),
            $this->_prettyHexToBin($vector['iv_hex']),
            $vector['version']
        );

        $this->assertEquals($vector['ciphertext_hex'], $this->_binToPrettyHex(base64_decode($encryptedB64)));
	}

    public function testPasswordVectorOneByte() {

        $vector = $this->_getVectors('password')[1];

        $encryptor = new Encryptor();
        $encryptedB64 = $encryptor->encryptWithArbitrarySalts(
            $this->_prettyHexToBin($vector['plaintext_hex']),
            $vector['password'],
            $this->_prettyHexToBin($vector['enc_salt_hex']),
            $this->_prettyHexToBin($vector['hmac_salt_hex']),
            $this->_prettyHexToBin($vector['iv_hex']),
            $vector['version']
        );

        $this->assertEquals($vector['ciphertext_hex'], $this->_binToPrettyHex(base64_decode($encryptedB64)));
    }

    public function testPasswordVectorExactlyOneBlock() {

        $vector = $this->_getVectors('password')[2];

        $encryptor = new Encryptor();
        $encryptedB64 = $encryptor->encryptWithArbitrarySalts(
            $this->_prettyHexToBin($vector['plaintext_hex']),
            $vector['password'],
            $this->_prettyHexToBin($vector['enc_salt_hex']),
            $this->_prettyHexToBin($vector['hmac_salt_hex']),
            $this->_prettyHexToBin($vector['iv_hex']),
            $vector['version']
        );

        $this->assertEquals($vector['ciphertext_hex'], $this->_binToPrettyHex(base64_decode($encryptedB64)));
    }

    public function testPasswordVectorMoreThanOneBlock() {

        $vector = $this->_getVectors('password')[3];

        $encryptor = new Encryptor();
        $encryptedB64 = $encryptor->encryptWithArbitrarySalts(
            $this->_prettyHexToBin($vector['plaintext_hex']),
            $vector['password'],
            $this->_prettyHexToBin($vector['enc_salt_hex']),
            $this->_prettyHexToBin($vector['hmac_salt_hex']),
            $this->_prettyHexToBin($vector['iv_hex']),
            $vector['version']
        );

        $this->assertEquals($vector['ciphertext_hex'], $this->_binToPrettyHex(base64_decode($encryptedB64)));
    }

    private function _prettyHexToBin($data) {
		return hex2bin(preg_replace("/[^a-z0-9]/i", '', $data));
	}

	private function _binToPrettyHex($data) {

		$hex = bin2hex($data);

		$prettyHex = '';
		foreach (str_split($hex, 8) as $index => $part) {
			$prettyHex .= ($index != 0 ? ' ' : '') . $part;
		}
		return $prettyHex;
	}

	private function _getVectors($filename) {

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
