<?php

namespace uofa\Encryption;

use Illuminate\Support\ServiceProvider;


class EncryptionServiceProvider extends ServiceProvider
{
    public function register()
    {
        $this->app->bindShared('encrypter', function ($app) {
            if ($app['config']->has('app.cipher')) {
                return new Encrypter(
                    $app['config']['app.key'],
                    $app['config']['app.cipher']
                );
            } else {
                return new Encrypter($app['config']['app.key']);
            }
        });
        $this->app->alias('encrypter', Encrypter::class);
    }
}