RNCryptor PHP
-------------

[![Build Status](https://travis-ci.org/RNCryptor/RNCryptor-php.svg?branch=master)](https://travis-ci.org/RNCryptor/RNCryptor-php)

This implementation strives to be fully compatible with Rob Napier's
Objective-C implementation of RNCryptor.  It supports both encryption and
decryption of all RNCryptor schema versions through version 3.  Due to security
concerns with schemas 0 through 2, it is strongly recommended to use schema 3
wherever possible.  This is the default if none is specified.

Basic usage is seen in the examples folder.
