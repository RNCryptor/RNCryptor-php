<?php
namespace Tests\RNCryptor;

use PHPUnit\Framework\TestCase;
use RNCryptor\RNCryptor\Decryptor;

class DecryptorTest extends TestCase
{

    const IOS_PASSWORD = 'mypassword123$!';

    const PLAINTEXT_V0_LESS_THAN_ONE_BLOCK = 'Monkey';
    const IOS_ENCRYPTED_V0_LESS_THAN_ONE_BLOCK
        = 'AACoGb/5NAItZ9gY0YkCXK0Q7d+1p2mNyFFKIDldCA5QRqX5i9MNpezRS7CDX8jUDKGtIlZU6d8CZQeJAAAAAAAAAAAAAAAA';
    
    const PLAINTEXT_V0_EXACTLY_ONE_BLOCK = 'O happy day now.';
    const IOS_ENCRYPTED_V0_EXACTLY_ONE_BLOCK
        = 'AADsM/JbTInOMSm0epc/7MqQ1Ol2Fu/ySnQ0FknhJeTD6GpZo+SF8JDloHN82yZIHrOcJ3vZuXmrCUt3AysLYg6Vpu4KDwAAAAAAAAAAAAAA'
        . 'AA==';
    
    const PLAINTEXT_V0_EXACTLY_TWO_BLOCKS = 'Earth is round, sun is round too';
    const IOS_ENCRYPTED_V0_EXACTLY_TWO_BLOCKS
        = 'AAApp4OoYpg4Fz+WSZDbcf5KPJasOkhdCnptrmwVkt58BZi/lnTWoIOf2IhIZhHsvTKYYEJsds6bFL/nZC/GtENusHWFyEw1IdtQ7KFSp8XZ'
        . 'EhiAT88AAAAAAAAAAAAAAAA=';
    
    const PLAINTEXT_V0_NON_BLOCK_INTERVAL = 'Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do...';
    const IOS_ENCRYPTED_V0_NON_BLOCK_INTERVAL
        = 'AADu55As8qH9KsSR17p1akydMUlbHrsHudMOr/yTj4olfQedJPTZg8hK4ua99zNkj3Nw7Hle1f1onHclWIYoLkWtMVk4Cp96CcxRhaWbBZqA'
        . 'VvTabtVruxcAi+GEB2K4rrmyARxB2QJH9tfz2yTFoFNMln+xOCUm0wAAAAAAAAAAAAAAAA==';
    
    const PLAINTEXT_V1_EXACTLY_ONE_BLOCK = 'Lorem ipsum dolor sit amet, cons';
    const IOS_ENCRYPTED_V1_EXACTLY_ONE_BLOCK
        = 'AQEjdvTrgCAo8UMn9omCd30um3iMfq/Swiglr5I/wAESEuHBcdbtpbqpUliyDs6NyI83SQGzV9wpAdW8EYBzGdJ1AcE/nld27XX9jPF4Fj+X'
        . '++Ws4EL2gEoJYO1fGuX3+hUFhIWaPCzxg/HvLMTDVq4k';
    
    const PLAINTEXT_V1_NON_BLOCK_INTERVAL = 'Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do...';
    const IOS_ENCRYPTED_V1_NON_BLOCK_INTERVAL
        = 'AQE9u3aB1APkWDRHcfy1cvD3kwwoXUw+8JhtCkZ3xDkSQghIyFoqLgazX3cXBxv3Mj75sSofHoDI35KaFTdXovY3HQYAaQmMdPNvSRVGvlpt'
        . 'kyr5LSBMUA3/Uj7lmhnaf515pN8pUbcbOV8RP+oWhXX4iKN009mrcMaX2j1KQz2JfFj8bfpbu9BOtj+1NotIe14=';
    
    const PLAINTEXT_V2_EXACTLY_ONE_BLOCK = 'Lorem ipsum dolor sit amet, cons';
    const IOS_ENCRYPTED_V2_EXACTLY_ONE_BLOCK
        = 'AgEjDKHOcviYJbHBiZ4l0sku8Dd+0EZIUEz69uTtQI/yJorbiCu3mxpbTVrM6Kj4/vywmOdXdwSR0ov2S/oJ1rVtA8gJ2ulKyrYOOySfDS0/'
        . 'YioWKe21zJMfizK8PHveyjBoKmIJdPhT5/caF3l/+JCs';
    
    const PLAINTEXT_V2_NON_BLOCK_INTERVAL = 'Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do...';
    const IOS_ENCRYPTED_V2_NON_BLOCK_INTERVAL
        = 'AgG8X+ixN6HN9zFnuK1NMJAPntIuC0+WPsmFhGL314zLuq1T9xWDHYzpnzW8EqDz81Amj36+EqrjazQ1gO9ao6bpMwUKdT2xY4ZUrhtCQm3L'
        . 'D2okbEIGjj5dtMJtB3i759WdnmNf8K0ULDWNzNQHPzdNDcEE2BPh+2kRaqVzWyBOzJppJoD5n+WdglS7BEBU+4U=';

    public function testCanDecryptIosEncryptedVersion0WithPlaintextLengthLessThanOneBlock()
    {
        $decryptor = new Decryptor;
        $decrypted = $decryptor->decrypt(self::IOS_ENCRYPTED_V0_LESS_THAN_ONE_BLOCK, self::IOS_PASSWORD);
        $this->assertEquals(self::PLAINTEXT_V0_LESS_THAN_ONE_BLOCK, $decrypted);
    }

    public function testCanDecryptIosEncryptedVersion0WithPlaintextReallyLong()
    {
        $decryptor = new Decryptor;
        $decrypted = $decryptor->decrypt(
            file_get_contents(__DIR__ . '/../files/lorem-ipsum-encrypted-base64-schema0.txt'),
            self::IOS_PASSWORD
        );
        $this->assertEquals(file_get_contents(__DIR__ . '/../files/lorem-ipsum.txt'), $decrypted);
    }

    public function testCanDecryptIosEncryptedVersion0WithPlaintextLengthExactlyOneBlock()
    {
        $decryptor = new Decryptor;
        $decrypted = $decryptor->decrypt(self::IOS_ENCRYPTED_V0_EXACTLY_ONE_BLOCK, self::IOS_PASSWORD);
        $this->assertEquals(self::PLAINTEXT_V0_EXACTLY_ONE_BLOCK, $decrypted);
    }

    public function testCanDecryptIosEncryptedVersion0WithPlaintextLengthExactlyTwoBlocks()
    {
        $decryptor = new Decryptor;
        $decrypted = $decryptor->decrypt(self::IOS_ENCRYPTED_V0_EXACTLY_TWO_BLOCKS, self::IOS_PASSWORD);
        $this->assertEquals(self::PLAINTEXT_V0_EXACTLY_TWO_BLOCKS, $decrypted);
    }
    
    public function testCanDecryptIosEncryptedVersion0WithPlaintextLengthNotOnBlockInterval()
    {
        $decryptor = new Decryptor;
        $decrypted = $decryptor->decrypt(self::IOS_ENCRYPTED_V0_NON_BLOCK_INTERVAL, self::IOS_PASSWORD);
        $this->assertEquals(self::PLAINTEXT_V0_NON_BLOCK_INTERVAL, $decrypted);
    }

    public function testCanDecryptIosEncryptedVersion1WithPlaintextReallyLong()
    {
        $decryptor = new Decryptor;
        $decrypted = $decryptor->decrypt(
            file_get_contents(__DIR__ . '/../files/lorem-ipsum-encrypted-base64-schema1.txt'),
            self::IOS_PASSWORD
        );
        $this->assertEquals(file_get_contents(__DIR__ . '/../files/lorem-ipsum.txt'), $decrypted);
    }

    public function testCanDecryptIosEncryptedVersion1WithPlaintextLengthExactlyOneBlock()
    {
        $decryptor = new Decryptor;
        $decrypted = $decryptor->decrypt(self::IOS_ENCRYPTED_V1_EXACTLY_ONE_BLOCK, self::IOS_PASSWORD);
        $this->assertEquals(self::PLAINTEXT_V1_EXACTLY_ONE_BLOCK, $decrypted);
    }

    public function testCanDecryptIosEncryptedVersion1WithPlaintextLengthNotOnBlockInterval()
    {
        $decryptor = new Decryptor;
        $decrypted = $decryptor->decrypt(self::IOS_ENCRYPTED_V1_NON_BLOCK_INTERVAL, self::IOS_PASSWORD);
        $this->assertEquals(self::PLAINTEXT_V1_NON_BLOCK_INTERVAL, $decrypted);
    }

    public function testCanDecryptIosEncryptedVersion2WithPlaintextReallyLong()
    {
        $decryptor = new Decryptor;
        $decrypted = $decryptor->decrypt(
            file_get_contents(__DIR__ . '/../files/lorem-ipsum-encrypted-base64-schema2.txt'),
            self::IOS_PASSWORD
        );
        $this->assertEquals(file_get_contents(__DIR__ . '/../files/lorem-ipsum.txt'), $decrypted);
    }

    public function testCanDecryptIosEncryptedVersion2WithPlaintextLengthExactlyOneBlock()
    {
        $decryptor = new Decryptor;
        $decrypted = $decryptor->decrypt(self::IOS_ENCRYPTED_V2_EXACTLY_ONE_BLOCK, self::IOS_PASSWORD);
        $this->assertEquals(self::PLAINTEXT_V2_EXACTLY_ONE_BLOCK, $decrypted);
    }

    public function testCanDecryptIosEncryptedVersion2WithPlaintextLengthNotOnBlockInterval()
    {
        $decryptor = new Decryptor;
        $decrypted = $decryptor->decrypt(self::IOS_ENCRYPTED_V2_NON_BLOCK_INTERVAL, self::IOS_PASSWORD);
        $this->assertEquals(self::PLAINTEXT_V2_NON_BLOCK_INTERVAL, $decrypted);
    }

    public function testDecryptingWithBadPasswordFails()
    {
        $decryptor = new Decryptor;
        $decrypted = $decryptor->decrypt(self::IOS_ENCRYPTED_V2_NON_BLOCK_INTERVAL, 'bad-password');
        $this->assertEquals(false, $decrypted);
    }

    public function testCanSetCustomIterations()
    {
        $decryptor = new Decryptor;
        $decryptor->setIterations(42);

        $this->assertEquals(42, $decryptor->getIterations());
    }
}
