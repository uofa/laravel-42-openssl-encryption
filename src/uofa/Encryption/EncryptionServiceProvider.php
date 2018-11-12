<?php

namespace uofa\Encryption;

use Illuminate\Support\ServiceProvider;

class EncryptionServiceProvider extends ServiceProvider
{
    public function register()
    {
        $this->app->bindShared('encrypter', function ($app) {
            if (Str::startsWith($key = $app['config']['app.key'], 'base64:')) {
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
