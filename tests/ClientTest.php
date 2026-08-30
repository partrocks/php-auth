<?php

declare(strict_types=1);

namespace PartRocks\Auth\Tests;

use PartRocks\Auth\Client;
use PartRocks\Auth\PartRocksError;
use PHPUnit\Framework\TestCase;

final class ClientTest extends TestCase
{
    public function testSendsApiKeyAndBearer(): void
    {
        $captured = [];
        $client = Client::create('https://auth.example/', 'prk_test', function (string $method, string $url, array $headers, ?string $body) use (&$captured): array {
            $captured = compact('method', 'url', 'headers', 'body');

            return ['status' => 200, 'body' => '{"teams":[]}'];
        });

        $client->listTeams('jwt');

        self::assertSame('GET', $captured['method']);
        self::assertSame('https://auth.example/api/v2/teams', $captured['url']);
        self::assertSame('prk_test', $captured['headers']['X-API-Key']);
        self::assertSame('Bearer jwt', $captured['headers']['Authorization']);
    }

    public function testThrowsPartRocksError(): void
    {
        $client = Client::create('https://auth.example', 'prk_test', fn (): array => [
            'status' => 401,
            'body' => '{"error":"The username or password is invalid.","code":"invalid_credentials"}',
        ]);

        try {
            $client->createSession(['username' => 'a', 'password' => 'b']);
            self::fail('Expected PartRocksError');
        } catch (PartRocksError $error) {
            self::assertSame('invalid_credentials', $error->errorCode);
            self::assertSame(401, $error->status);
        }
    }

    public function testPostsUserBody(): void
    {
        $captured = [];
        $client = Client::create('https://auth.example', 'prk_test', function (string $method, string $url, array $headers, ?string $body) use (&$captured): array {
            $captured = compact('method', 'url', 'body');

            return ['status' => 201, 'body' => '{"user":{"id":"u1"}}'];
        });

        $result = $client->createUser(['username' => 'alex@example.com', 'password' => 'secret']);

        self::assertSame('POST', $captured['method']);
        self::assertSame('https://auth.example/api/v1/users', $captured['url']);
        self::assertSame('{"username":"alex@example.com","password":"secret"}', $captured['body']);
        self::assertSame('u1', $result['user']['id']);
    }
}
