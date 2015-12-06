<?php

/*
 * This file is part of the RNCryptor package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

if (file_exists(__DIR__.'/../vendor/autoload.php')) {
    require __DIR__.'/../vendor/autoload.php';

} else if (@include('RNCryptor/Autoloader.php')) {
    RNCryptor\Autoloader::register();

} else {
    die('ERROR: Unable to find a suitable mean to register RNCryptor\Autoloader.');
}
