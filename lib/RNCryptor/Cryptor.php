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

	protected function _generateKey($salt, $password) {

		if ($this->_settings->truncatesMultibytePasswords) {
			$utf8Length = mb_strlen($password, 'utf-8');
			$password = substr($password, 0, $utf8Length);
		}

		//return hash_pbkdf2($this->_settings->pbkdf2->prf, $password, $salt, $this->_settings->pbkdf2->iterations, $this->_settings->pbkdf2->keyLength, true);
                return $this->pbkdf2($this->_settings->pbkdf2->prf, $password, $salt, $this->_settings->pbkdf2->iterations, $this->_settings->pbkdf2->keyLength, true);
	}
	
        /*
         * PBKDF2 key derivation function as defined by RSA's PKCS #5: https://www.ietf.org/rfc/rfc2898.txt
         * $algorithm - The hash algorithm to use. Recommended: SHA256
         * $password - The password.
         * $salt - A salt that is unique to the password.
         * $count - Iteration count. Higher is better, but slower. Recommended: At least 1000.
         * $key_length - The length of the derived key in bytes.
         * $raw_output - If true, the key is returned in raw binary format. Hex encoded otherwise.
         * Returns: A $key_length-byte key derived from the password and salt.
         *
         * Test vectors can be found here: https://www.ietf.org/rfc/rfc6070.txt
         *
         * This implementation of PBKDF2 was originally created by https://defuse.ca
         * With improvements by http://www.variations-of-shadow.com
         */
        function pbkdf2($algorithm, $password, $salt, $count, $key_length, $raw_output = false)
        {
            $algorithm = strtolower($algorithm);
            if(!in_array($algorithm, hash_algos(), true))
                die('PBKDF2 ERROR: Invalid hash algorithm.');
            if($count <= 0 || $key_length <= 0)
                die('PBKDF2 ERROR: Invalid parameters.');

            $hash_length = strlen(hash($algorithm, "", true));
            $block_count = ceil($key_length / $hash_length);

            $output = "";
            for($i = 1; $i <= $block_count; $i++) {
                // $i encoded as 4 bytes, big endian.
                $last = $salt . pack("N", $i);
                // first iteration
                $last = $xorsum = hash_hmac($algorithm, $last, $password, true);
                // perform the other $count - 1 iterations
                for ($j = 1; $j < $count; $j++) {
                    $xorsum ^= ($last = hash_hmac($algorithm, $last, $password, true));
                }
                $output .= $xorsum;
            }

            if($raw_output)
                return substr($output, 0, $key_length);
            else
                return bin2hex(substr($output, 0, $key_length));
        }


}
