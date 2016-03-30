<?php
namespace RNCryptor;

class Cryptor {

	const DEFAULT_SCHEMA_VERSION = 3;

	protected $_settings;

	public function __construct() {
		if (!extension_loaded('mcrypt')) {
			throw new \Exception('The mcrypt extension is missing.');
		}
	}

	protected function _configureSettings($version) {

		$settings = new \stdClass();

		$settings->algorithm = MCRYPT_RIJNDAEL_128;
		$settings->saltLength = 8;
		$settings->ivLength = 16;

		$settings->pbkdf2 = new \stdClass();
		$settings->pbkdf2->prf = 'sha1';
		$settings->pbkdf2->iterations = 10000;
		$settings->pbkdf2->keyLength = 32;
		
		$settings->hmac = new \stdClass();
		$settings->hmac->length = 32;

		switch ($version) {
			case 0:
				$settings->mode = 'ctr';
				$settings->options = 0;
				$settings->hmac->includesHeader = false;
				$settings->hmac->algorithm = 'sha1';
				$settings->hmac->includesPadding = true;
				$settings->truncatesMultibytePasswords = true;
				break;

			case 1:
				$settings->mode = 'cbc';
				$settings->options = 1;
				$settings->hmac->includesHeader = false;
				$settings->hmac->algorithm = 'sha256';
				$settings->hmac->includesPadding = false;
				$settings->truncatesMultibytePasswords = true;
				break;

			case 2:
				$settings->mode = 'cbc';
				$settings->options = 1;
				$settings->hmac->includesHeader = true;
				$settings->hmac->algorithm = 'sha256';
				$settings->hmac->includesPadding = false;
				$settings->truncatesMultibytePasswords = true;
				break;

			case 3:
				$settings->mode = 'cbc';
				$settings->options = 1;
				$settings->hmac->includesHeader = true;
				$settings->hmac->algorithm = 'sha256';
				$settings->hmac->includesPadding = false;
				$settings->truncatesMultibytePasswords = false;
				break;

			default:
				throw new \Exception('Unsupported schema version ' . $version);
		}

		$this->_settings = $settings;
	}

	/**
	 * Encrypt or decrypt using AES CTR Little Endian mode
	 */
	protected function _aesCtrLittleEndianCrypt($payload, $key, $iv) {

		$numOfBlocks = ceil(strlen($payload) / strlen($iv));
		$counter = '';
		for ($i = 0; $i < $numOfBlocks; ++$i) {
			$counter .= $iv;

			// Yes, the next line only ever increments the first character
			// of the counter string, ignoring overflow conditions.  This
			// matches CommonCrypto's behavior!
			$iv[0] = chr(ord($iv[0]) + 1);
		}

		return $payload ^ mcrypt_encrypt($this->_settings->algorithm, $key, $counter, 'ecb');
	}

	protected function _generateHmac(\stdClass $components, $hmacKey) {
	
		$hmacMessage = '';
		if ($this->_settings->hmac->includesHeader) {
			$hmacMessage .= $components->headers->version
							. $components->headers->options
							. (isset($components->headers->encSalt) ? $components->headers->encSalt : '')
							. (isset($components->headers->hmacSalt) ? $components->headers->hmacSalt : '')
							. $components->headers->iv;
		}

		$hmacMessage .= $components->ciphertext;

		$hmac = hash_hmac($this->_settings->hmac->algorithm, $hmacMessage, $hmacKey, true);

		if ($this->_settings->hmac->includesPadding) {
			$hmac = str_pad($hmac, $this->_settings->hmac->length, chr(0));
		}
	
		return $hmac;
	}

	/**
	 * Key derivation -- This method is intended for testing.  It merely
	 * exposes the underlying key-derivation functionality.
	 */
	public function generateKey($salt, $password, $version = self::DEFAULT_SCHEMA_VERSION) {
		$this->_configureSettings($version);
		return $this->_generateKey($salt, $password);
	}

	public function generateKeyWithoutSalt($password, $version = self::DEFAULT_SCHEMA_VERSION) {
		$this->_configureSettings($version);
		$salt = $this->_generateSalt();
		return $this->_generateKey($salt, $password);
	}

	private function _generateSalt() {
		return $this->_generateIv($this->_settings->saltLength);
	}

	protected function _generateKey($salt, $password) {

		if ($this->_settings->truncatesMultibytePasswords) {
			$utf8Length = mb_strlen($password, 'utf-8');
			$password = substr($password, 0, $utf8Length);
		}

		return hash_pbkdf2($this->_settings->pbkdf2->prf, $password, $salt, $this->_settings->pbkdf2->iterations, $this->_settings->pbkdf2->keyLength, true);
	}

	private function _generateIv($blockSize) {
		if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN') {
			$randomSource = MCRYPT_RAND;
		} else {
			$randomSource = MCRYPT_DEV_URANDOM;
		}
		return mcrypt_create_iv($blockSize, $randomSource);
	}

}
