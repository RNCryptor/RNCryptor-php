<?php

require __DIR__ . '/../vendor/autoload.php';

$password = "myPassword";
$base64Encrypted = "AgGXutvFqW9RqQuokYLjehbfM7F+8OO/2sD8g3auA+oNCQFoarRmc59qcKJve7FHyH9MkyJWZ4Cj6CegDU+UbtpXKR0ND6Ulfwa'
    . 'ZncRUNkw53jy09cgUkHRJI0gCfOsS4rXmRdiaqUt+ukkkaYfAJJk/o3HBvqK/OI4qttyo+kdiLbiAop5QQwWReG2LMQ08v9TAiiOQgFWhd1dc+qF'
    . 'EN7Cv";

$cryptor = new \RNCryptor\RNCryptor\Decryptor;
$plaintext = $cryptor->decrypt($base64Encrypted, $password);

echo "Base64 Encrypted:\n$base64Encrypted\n\n";
echo "Plaintext:\n$plaintext\n\n";
