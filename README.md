RNCryptor PHP
-------------

[![Build Status](https://travis-ci.org/RNCryptor/RNCryptor-php.svg?branch=master)](https://travis-ci.org/RNCryptor/RNCryptor-php)

This implementation strives to be fully compatible with Rob Napier's
Objective-C implementation of RNCryptor.  It supports both encryption and
decryption of all RNCryptor schema versions through version 3.  Due to security
concerns with schemas 0 through 2, it is strongly recommended to use schema 3
wherever possible.  This is the default if none is specified.

Basic usage is seen in the examples folder.

## Installation

This library assumes you are using [Composer](http://getcomposer.org) for dependency management.

```
composer require rncryptor/rncryptor
```

If your project itself does not use Composer, then it's about time that it did. ;-)  We strongly urge using it.  Otherwise you will have to manually read `composer.json` and make sure the named dependencies are properly loaded into your project.

## FAQ

### It's complaining about a missing function called `hash_pbkdf2`

This error almost certainly means that this project's dependencies are not installed or being autoloaded properly.  See the Installation section above for more.

### It won't decrypt. The "+" on the sending end is getting turned into a " " on the receiving end.

This is usually due to passing an encrypted string into an HTTP request without taking care to encode it for HTTP first.  It's because Base64 (which RNCryptor's encrypted strings are encoded in) sometimes includes the "+" character in its output, but this character has special meaning in HTTP encoding.

You can most likely solve this by passing the encrypted string through `rawurlencode()` on the sending end  (or whatever is the equivalent for the language you are working with) before passing it into your HTTP request.  And on the receiving end, you might need to use `rawurldecode()` on the string if your framework isn't already doing this for you.
