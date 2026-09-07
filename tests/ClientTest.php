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

            return ['status' => 200, 'body' => '{"organisations":[]}'];
        });

        $client->listOrganisations('jwt');

        self::assertSame('GET', $captured['method']);
        self::assertSame('https://auth.example/api/v2/organisations', $captured['url']);
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

    public function testMapsTheCompleteOrganisationsApi(): void
    {
        $calls = [];
        $client = Client::create('https://auth.example', 'prk_test', function (string $method, string $url, array $headers, ?string $body) use (&$calls): array {
            $calls[] = compact('method', 'url', 'body');

            return ['status' => 200, 'body' => '{}'];
        });

        $client->createOrganisation(['name' => 'Acme', 'slug' => 'acme'], 'jwt');
        $client->getOrganisation('o1', 'jwt');
        $client->updateOrganisation('o1', ['name' => 'Acme Ltd'], 'jwt');
        $client->deleteOrganisation('o1', 'jwt');
        $client->getCurrentOrganisationMembership('o1', 'jwt');
        $client->leaveOrganisation('o1', 'jwt');
        $client->listOrganisationMembers('o1', 'jwt');
        $client->addOrganisationMember('o1', ['userId' => 'u1', 'role' => 'admin'], 'jwt');
        $client->changeOrganisationMemberRole('o1', 'u1', ['role' => 'user'], 'jwt');
        $client->removeOrganisationMember('o1', 'u1', 'jwt');
        $client->listOrganisationInvitations('o1', 'jwt');
        $client->revokeOrganisationInvitation('o1', 'i1', 'jwt');

        self::assertSame([
            'POST https://auth.example/api/v2/organisations',
            'GET https://auth.example/api/v2/organisations/o1',
            'PATCH https://auth.example/api/v2/organisations/o1',
            'DELETE https://auth.example/api/v2/organisations/o1',
            'GET https://auth.example/api/v2/organisations/o1/membership',
            'DELETE https://auth.example/api/v2/organisations/o1/membership',
            'GET https://auth.example/api/v2/organisations/o1/members',
            'POST https://auth.example/api/v2/organisations/o1/members',
            'PATCH https://auth.example/api/v2/organisations/o1/members/u1',
            'DELETE https://auth.example/api/v2/organisations/o1/members/u1',
            'GET https://auth.example/api/v2/organisations/o1/invitations',
            'DELETE https://auth.example/api/v2/organisations/o1/invitations/i1',
        ], array_map(static fn (array $call): string => $call['method'].' '.$call['url'], $calls));
        self::assertSame('{"userId":"u1","role":"admin"}', $calls[7]['body']);
        self::assertSame('{"role":"user"}', $calls[8]['body']);
    }

    public function testSendsOrganisationInvitationMailFromReturnedLink(): void
    {
        $sent = [];
        $requestUrl = null;
        $client = Client::create('https://auth.example', 'prk_test', function (string $method, string $url) use (&$requestUrl): array {
            $requestUrl = $url;

            return [
                'status' => 201,
                'body' => '{"invited":true,"link":"https://app.example/invite?token=tok"}',
            ];
        });
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

        $client->createOrganisationInvitation(
            'o1',
            ['email' => 'invitee@example.com'],
            'jwt',
            ['sendMail' => ['mail' => $mail, 'application' => 'Acme']],
        );

        self::assertSame('https://auth.example/api/v2/organisations/o1/invitations', $requestUrl);
        self::assertSame('organisation-invitation', $sent[0]['template']);
        self::assertSame('invitee@example.com', $sent[0]['to']);
        self::assertSame('https://app.example/invite?token=tok', $sent[0]['metadata']['link']);
    }

    public function testAcceptsInvitationWithBearerTokenOrPassword(): void
    {
        $calls = [];
        $client = Client::create('https://auth.example', 'prk_test', function (string $method, string $url, array $headers, ?string $body) use (&$calls): array {
            $calls[] = compact('headers', 'body');

            return ['status' => 200, 'body' => '{"organisation":{"id":"o1","role":"user"}}'];
        });

        $client->acceptInvitation('tok', ['accessToken' => 'jwt']);
        $client->acceptInvitation('tok', ['password' => 'new-password']);

        self::assertSame('Bearer jwt', $calls[0]['headers']['Authorization']);
        self::assertNull($calls[0]['body']);
        self::assertArrayNotHasKey('Authorization', $calls[1]['headers']);
        self::assertSame('{"password":"new-password"}', $calls[1]['body']);
    }

    public function testAcceptInvitationRequiresCredentials(): void
    {
        $client = Client::create('https://auth.example', 'prk_test', fn (): array => [
            'status' => 200,
            'body' => '{}',
        ]);

        $this->expectException(\InvalidArgumentException::class);
        $client->acceptInvitation('tok', []);
    }
}
