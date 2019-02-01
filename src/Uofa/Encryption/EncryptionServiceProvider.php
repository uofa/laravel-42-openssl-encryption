<?php

namespace Uofa\Encryption;

use Illuminate\Support\ServiceProvider;
use Illuminate\Support\Str;

class EncryptionServiceProvider extends ServiceProvider
{
    public function register()
    {
        $this->app->bindShared('encrypter', function ($app) {
            $key = (string) $app['config']['app.key'];
            if (Str::startsWith($key, 'base64:')) {
                $key = base64_decode(substr($key, 7));
            }

            if ($app['config']->has('app.cipher')) {
                return new Encrypter(
                    $key,
                    $app['config']['app.cipher']
                );
            } else {
                return new Encrypter($key);
            }
        });
        $this->app->alias('encrypter', Encrypter::class);
    }
}
