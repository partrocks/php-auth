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

    public function testSendsWelcomeMailAfterUserCreateWithoutRollingBack(): void
    {
        $sent = [];
        $client = Client::create('https://auth.example', 'prk_test', fn (): array => [
            'status' => 201,
            'body' => '{"user":{"id":"u1"}}',
        ]);
        $mail = new class($sent) {
            /** @param list<array<string, mixed>> $sent */
            public function __construct(private array &$sent)
            {
            }

            /** @param array<string, mixed> $body */
            public function send(array $body): never
            {
                $this->sent[] = $body;
                throw new \RuntimeException('smtp down');
            }
        };

        $result = $client->createUser(
            ['username' => 'alex@example.com', 'password' => 'secret'],
            ['sendWelcomeMail' => ['mail' => $mail, 'application' => 'Acme']],
        );

        self::assertSame('u1', $result['user']['id']);
        self::assertFalse($result['mailSent']);
        self::assertSame('smtp down', $result['mailError']);
        self::assertSame('welcome', $sent[0]['template']);
        self::assertSame('alex@example.com', $sent[0]['to']);
    }

    public function testSendsPasswordResetMailFromReturnedLink(): void
    {
        $sent = [];
        $client = Client::create('https://auth.example', 'prk_test', fn (): array => [
            'status' => 200,
            'body' => '{"accepted":true,"token":"tok","link":"https://app.example/reset?token=tok"}',
        ]);
        $mail = new class($sent) {
            /** @param list<array<string, mixed>> $sent */
            public function __construct(private array &$sent)
            {
            }

            /** @param array<string, mixed> $body */
            public function send(array $body): array
            {
                $this->sent[] = $body;

                return ['message' => ['id' => 'm1']];
            }
        };

        $result = $client->requestPasswordReset(
            ['email' => 'alex@example.com'],
            ['sendMail' => ['mail' => $mail, 'application' => 'Acme']],
        );

        self::assertTrue($result['accepted']);
        self::assertTrue($result['mailSent']);
        self::assertSame('password-reset', $sent[0]['template']);
        self::assertSame('https://app.example/reset?token=tok', $sent[0]['metadata']['link']);
    }
}
