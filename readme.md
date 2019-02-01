# Laravel 4.2 update to use AES-128-CBC/AES-256-CBC

As of `PHP 7.1.0` mcrypt has been deprecated. Laravel 4.2 Encrypter is using mcrypt, however, it can be updated to use either `AES-128-CBC` or `AES-256-CBC`.

## Instructions

  - Install this library `composer require uofa/laravel42-encrypter`.
  - Include a line `'Uofa\Encryption\EncryptionServiceProvider'` at the end of your providers array in `config/app.php`.
  - Generate new key by running `php artisan key:generate`