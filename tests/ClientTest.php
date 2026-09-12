<?php

declare(strict_types=1);

namespace PartRocks\Auth\Tests;

use PartRocks\Auth\Client;
use PartRocks\Auth\PartRocksError;
use PHPUnit\Framework\TestCase;
use ReflectionMethod;

final class ClientTest extends TestCase
{
    public function testHasNoCapabilityClientDependencies(): void
    {
        $package = json_decode((string) file_get_contents(__DIR__.'/../composer.json'), true, flags: JSON_THROW_ON_ERROR);

        self::assertArrayNotHasKey('partrocks/analytics', $package['require']);
        self::assertArrayNotHasKey('partrocks/mail', $package['require']);
        self::assertArrayNotHasKey('partrocks/secrets', $package['require']);
    }

    public function testCreateHasNoEnvironmentArgument(): void
    {
        $method = new ReflectionMethod(Client::class, 'create');
        $names = array_map(
            static fn (\ReflectionParameter $parameter): string => $parameter->getName(),
            $method->getParameters(),
        );

        self::assertSame(['apiKey', 'baseUrl', 'transport'], $names);
        self::assertTrue($method->getParameters()[1]->allowsNull());
    }

    public function testDefaultsToHostedOriginWhenBaseUrlOmittedOrBlank(): void
    {
        $urls = [];
        $transport = function (string $method, string $url) use (&$urls): array {
            $urls[] = $url;

            return ['status' => 200, 'body' => '{"organisations":[]}'];
        };

        Client::create('prk_test', null, $transport)->listOrganisations('jwt');
        Client::create('prk_test', '   ', $transport)->listOrganisations('jwt');
        Client::create('prk_test', transport: $transport)->listOrganisations('jwt');

        self::assertSame([
            'https://auth.part.rocks/api/v2/organisations',
            'https://auth.part.rocks/api/v2/organisations',
            'https://auth.part.rocks/api/v2/organisations',
        ], $urls);
    }

    public function testSendsApiKeyAndBearer(): void
    {
        $captured = [];
        $client = Client::create('prk_test', 'https://auth.example/', function (string $method, string $url, array $headers, ?string $body) use (&$captured): array {
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
        $client = Client::create('prk_test', 'https://auth.example', fn (): array => [
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

    public function testThrowsPartRocksErrorForFinalAdminUserDelete(): void
    {
        $client = Client::create('prk_test', 'https://auth.example', fn (): array => [
            'status' => 409,
            'body' => '{"error":"The final organisation admin cannot be deleted.","code":"final_admin","organisations":[{"id":"11111111-1111-1111-1111-111111111111","name":"Acme"}]}',
        ]);

        try {
            $client->deleteUser('u1');
            self::fail('Expected PartRocksError');
        } catch (PartRocksError $error) {
            self::assertSame('final_admin', $error->errorCode);
            self::assertSame(409, $error->status);
            self::assertSame('The final organisation admin cannot be deleted.', $error->getMessage());
        }
    }

    public function testPostsUserBody(): void
    {
        $captured = [];
        $client = Client::create('prk_test', 'https://auth.example', function (string $method, string $url, array $headers, ?string $body) use (&$captured): array {
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
        $client = Client::create('prk_test', 'https://auth.example', fn (): array => [
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

    public function testSendsPasswordResetMailFromReturnedCode(): void
    {
        $sent = [];
        $client = Client::create('prk_test', 'https://auth.example', fn (): array => [
            'status' => 200,
            'body' => '{"accepted":true,"code":"123456","expiresAt":"2026-09-09T12:00:00Z"}',
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
        self::assertSame('123456', $sent[0]['metadata']['code']);
    }

    public function testDoesNotSendAccountActionMailWhenAuthOmitsCode(): void
    {
        $sendCount = 0;
        $client = Client::create('prk_test', 'https://auth.example', fn (): array => [
            'status' => 200,
            'body' => '{"accepted":true}',
        ]);
        $mail = new class($sendCount) {
            public function __construct(private int &$sendCount)
            {
            }

            /** @param array<string, mixed> $body */
            public function send(array $body): void
            {
                ++$this->sendCount;
            }
        };

        $result = $client->requestPasswordReset(
            ['email' => 'unknown@example.com'],
            ['sendMail' => ['mail' => $mail, 'application' => 'Acme']],
        );

        self::assertTrue($result['accepted']);
        self::assertArrayNotHasKey('mailSent', $result);
        self::assertSame(0, $sendCount);
    }

    public function testRequestsAndConfirmsAccountActionsWithEmailAndCodeBodies(): void
    {
        $calls = [];
        $client = Client::create('prk_test', 'https://auth.example', function (string $method, string $url, array $headers, ?string $body) use (&$calls): array {
            $calls[] = compact('url', 'headers', 'body');

            return ['status' => 200, 'body' => '{}'];
        });

        $client->requestEmailVerification(['email' => 'alex@example.com']);
        $client->confirmEmailVerification(['email' => 'alex@example.com', 'code' => '123456']);
        $client->confirmPasswordReset([
            'email' => 'alex@example.com',
            'code' => '654321',
            'password' => 'new-password',
        ]);

        self::assertSame('https://auth.example/api/v2/auth/email-verifications/request', $calls[0]['url']);
        self::assertSame('{"email":"alex@example.com"}', $calls[0]['body']);
        self::assertArrayNotHasKey('Authorization', $calls[0]['headers']);
        self::assertSame('https://auth.example/api/v2/auth/email-verifications/confirm', $calls[1]['url']);
        self::assertSame('{"email":"alex@example.com","code":"123456"}', $calls[1]['body']);
        self::assertArrayNotHasKey('Authorization', $calls[1]['headers']);
        self::assertSame('https://auth.example/api/v2/auth/password-resets/confirm', $calls[2]['url']);
        self::assertSame('{"email":"alex@example.com","code":"654321","password":"new-password"}', $calls[2]['body']);
        self::assertArrayNotHasKey('Authorization', $calls[2]['headers']);
    }

    public function testMapsTheCompleteOrganisationsApi(): void
    {
        $calls = [];
        $client = Client::create('prk_test', 'https://auth.example', function (string $method, string $url, array $headers, ?string $body) use (&$calls): array {
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

    public function testSendsOrganisationInvitationMailFromReturnedCode(): void
    {
        $sent = [];
        $requestUrl = null;
        $client = Client::create('prk_test', 'https://auth.example', function (string $method, string $url) use (&$requestUrl): array {
            $requestUrl = $url;

            return [
                'status' => 201,
                'body' => '{"invited":true,"code":"123456","expiresAt":"2026-09-09T12:00:00Z"}',
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
        self::assertSame('123456', $sent[0]['metadata']['code']);
    }

    public function testPassesSessionIdThroughOnCreateRefreshVerifyConfirmAndInviteSetup(): void
    {
        $sessionId = '11111111-1111-4111-8111-111111111111';
        $envelope = '{"token":"jwt","tokenType":"Bearer","expiresIn":300,"refreshToken":"rt","refreshExpiresIn":2592000,"sessionId":"'.$sessionId.'","user":{"id":"u1","username":"alex@example.com"}}';
        $verify = '{"valid":true,"expiresAt":"2026-09-12T12:00:00+00:00","sessionId":"'.$sessionId.'","user":{"id":"u1","username":"alex@example.com"}}';
        $client = Client::create('prk_test', 'https://auth.example', function (string $method, string $url) use ($envelope, $verify): array {
            $body = str_ends_with($url, '/api/v1/sessions/verify') ? $verify : $envelope;

            return ['status' => 200, 'body' => $body];
        });

        self::assertSame($sessionId, $client->createSession(['username' => 'a', 'password' => 'b'])['sessionId']);
        self::assertSame($sessionId, $client->refreshSession(['refreshToken' => 'rt'])['sessionId']);
        self::assertSame($sessionId, $client->verifySession('jwt')['sessionId']);
        self::assertSame($sessionId, $client->confirmEmailVerification(['email' => 'alex@example.com', 'code' => '123456'])['sessionId']);
        self::assertSame($sessionId, $client->acceptInvitation([
            'email' => 'new@example.com',
            'code' => '654321',
            'password' => 'new-password',
        ])['sessionId']);
    }

    public function testLogoutStillSendsOnlyRefreshToken(): void
    {
        $captured = [];
        $client = Client::create('prk_test', 'https://auth.example', function (string $method, string $url, array $headers, ?string $body) use (&$captured): array {
            $captured = compact('method', 'url', 'body');

            return ['status' => 204, 'body' => ''];
        });

        $result = $client->logout(['refreshToken' => 'rt']);

        self::assertNull($result);
        self::assertSame('POST', $captured['method']);
        self::assertSame('https://auth.example/api/v2/auth/logout', $captured['url']);
        self::assertSame('{"refreshToken":"rt"}', $captured['body']);
    }

    public function testAcceptsInvitationByBodyWithBearerTokenOrPassword(): void
    {
        $calls = [];
        $client = Client::create('prk_test', 'https://auth.example', function (string $method, string $url, array $headers, ?string $body) use (&$calls): array {
            $calls[] = compact('url', 'headers', 'body');

            return ['status' => 200, 'body' => '{"organisation":{"id":"o1","role":"user"}}'];
        });

        $client->acceptInvitation(['email' => 'alex@example.com', 'code' => '123456', 'accessToken' => 'jwt']);
        $client->acceptInvitation(['email' => 'new@example.com', 'code' => '654321', 'password' => 'new-password']);

        self::assertSame('https://auth.example/api/v2/invitations/accept', $calls[0]['url']);
        self::assertSame('Bearer jwt', $calls[0]['headers']['Authorization']);
        self::assertSame('{"email":"alex@example.com","code":"123456"}', $calls[0]['body']);
        self::assertSame('https://auth.example/api/v2/invitations/accept', $calls[1]['url']);
        self::assertArrayNotHasKey('Authorization', $calls[1]['headers']);
        self::assertSame('{"email":"new@example.com","code":"654321","password":"new-password"}', $calls[1]['body']);
    }

    public function testAcceptInvitationRequiresCredentials(): void
    {
        $client = Client::create('prk_test', 'https://auth.example', fn (): array => [
            'status' => 200,
            'body' => '{}',
        ]);

        $this->expectException(\InvalidArgumentException::class);
        $client->acceptInvitation([]);
    }

    public function testRecordsEveryMappedAuthSuccessWithAuthoritativeHelperMetadata(): void
    {
        $recorded = [];
        $recorder = new class($recorded) {
            /** @param list<array<string, mixed>> $recorded */
            public function __construct(private array &$recorded)
            {
            }

            /** @param array<string, mixed> $body */
            public function record(array $body): array
            {
                $this->recorded[] = $body;

                return ['recorded' => true];
            }
        };
        $analytics = (object) ['events' => $recorder];
        $baseRecord = [
            'analytics' => $analytics,
            'metadata' => [
                'plan' => 'pro',
                'source' => 'caller',
                'organisationId' => 'caller-org',
                'userId' => 'caller-user',
                'sessionId' => 'caller-session',
            ],
        ];
        $client = Client::create('prk_test', 'https://auth.example', static function (string $method, string $url, array $headers): array {
            $path = (string) parse_url($url, PHP_URL_PATH);
            if ('/api/v1/users' === $path) {
                return ['status' => 201, 'body' => '{"user":{"id":"u-operator"}}'];
            }
            if ('/api/v2/auth/register' === $path) {
                return ['status' => 201, 'body' => '{"user":{"id":"u-register"},"code":"123456"}'];
            }
            if ('/api/v1/sessions' === $path) {
                return ['status' => 201, 'body' => '{"user":{"id":"u-login"},"sessionId":"s-login"}'];
            }
            if ('/api/v2/auth/logout' === $path) {
                return ['status' => 204, 'body' => ''];
            }
            if ('/api/v2/auth/email-verifications/confirm' === $path) {
                return ['status' => 200, 'body' => '{"user":{"id":"u-verified"},"sessionId":"s-verified"}'];
            }
            if ('/api/v2/auth/password-resets/confirm' === $path) {
                return ['status' => 200, 'body' => '{"reset":true}'];
            }
            if ('/api/v2/organisations' === $path) {
                return ['status' => 201, 'body' => '{"organisation":{"id":"o-created"}}'];
            }
            if ('/api/v2/organisations/o-invite/invitations' === $path) {
                return ['status' => 201, 'body' => '{"invited":true,"code":"654321"}'];
            }
            if ('/api/v2/invitations/accept' === $path && isset($headers['Authorization'])) {
                return ['status' => 200, 'body' => '{"organisation":{"id":"o-accepted"}}'];
            }
            if ('/api/v2/invitations/accept' === $path) {
                return ['status' => 200, 'body' => '{"organisation":{"id":"o-setup"},"user":{"id":"u-setup"},"sessionId":"s-setup"}'];
            }
            if ('/api/v2/organisations/o-add/members' === $path) {
                return ['status' => 201, 'body' => '{"member":{"userId":"u-added"}}'];
            }
            if ('DELETE' === $method) {
                return ['status' => 204, 'body' => ''];
            }

            throw new \RuntimeException('Unexpected Auth request: '.$method.' '.$path);
        });

        $client->createUser(['username' => 'operator@example.com'], ['recordAnalytics' => $baseRecord]);
        $client->register(['email' => 'register@example.com', 'password' => 'password'], ['recordAnalytics' => $baseRecord]);
        $client->createSession(['username' => 'login@example.com', 'password' => 'password'], ['recordAnalytics' => $baseRecord]);
        $client->logout(['refreshToken' => 'rt'], ['recordAnalytics' => [
            'analytics' => $analytics,
            'metadata' => ['plan' => 'pro', 'userId' => 'u-logout', 'sessionId' => 's-logout'],
        ]]);
        $client->confirmEmailVerification(['email' => 'verified@example.com', 'code' => '123456'], ['recordAnalytics' => $baseRecord]);
        $client->confirmPasswordReset(
            ['email' => 'reset@example.com', 'code' => '123456', 'password' => 'password'],
            ['recordAnalytics' => ['analytics' => $analytics, 'metadata' => ['plan' => 'pro', 'userId' => 'u-reset']]],
        );
        $client->createOrganisation(['name' => 'Created', 'slug' => 'created'], 'jwt', ['recordAnalytics' => $baseRecord]);
        $client->createOrganisationInvitation('o-invite', ['email' => 'invitee@example.com'], 'jwt', ['recordAnalytics' => [
            'analytics' => $analytics,
            'metadata' => ['plan' => 'pro', 'organisationId' => 'caller-org', 'invitationId' => 'i-invite', 'inviterUserId' => 'u-inviter'],
        ]]);
        $client->acceptInvitation([
            'email' => 'member@example.com',
            'code' => '123456',
            'accessToken' => 'jwt',
            'recordAnalytics' => [
                'analytics' => $analytics,
                'metadata' => ['plan' => 'pro', 'organisationId' => 'caller-org', 'invitationId' => 'i-accepted', 'inviterUserId' => 'u-inviter', 'userId' => 'u-accepted'],
            ],
        ]);
        $client->acceptInvitation([
            'email' => 'new@example.com',
            'code' => '123456',
            'password' => 'password',
            'recordAnalytics' => [
                'analytics' => $analytics,
                'metadata' => ['plan' => 'pro', 'organisationId' => 'caller-org', 'invitationId' => 'i-setup', 'inviterUserId' => 'u-inviter', 'userId' => 'caller-user'],
            ],
        ]);
        $client->addOrganisationMember('o-add', ['userId' => 'u-added'], 'jwt', ['recordAnalytics' => $baseRecord]);
        $client->removeOrganisationMember('o-remove', 'u-removed', 'jwt', ['recordAnalytics' => $baseRecord]);
        $client->leaveOrganisation('o-leave', 'jwt', ['recordAnalytics' => [
            'analytics' => $analytics,
            'metadata' => ['plan' => 'pro', 'organisationId' => 'caller-org', 'userId' => 'u-left'],
        ]]);

        self::assertSame([
            ['metric' => 'auth.user_created', 'metadata' => array_replace($baseRecord['metadata'], ['userId' => 'u-operator', 'source' => 'operator'])],
            ['metric' => 'auth.user_created', 'metadata' => array_replace($baseRecord['metadata'], ['userId' => 'u-register', 'source' => 'register'])],
            ['metric' => 'auth.login', 'metadata' => array_replace($baseRecord['metadata'], ['userId' => 'u-login', 'sessionId' => 's-login'])],
            ['metric' => 'auth.logout', 'metadata' => ['plan' => 'pro', 'userId' => 'u-logout', 'sessionId' => 's-logout']],
            ['metric' => 'auth.email_verified', 'metadata' => array_replace($baseRecord['metadata'], ['userId' => 'u-verified'])],
            ['metric' => 'auth.password_reset_completed', 'metadata' => ['plan' => 'pro', 'userId' => 'u-reset']],
            ['metric' => 'auth.organisation_created', 'metadata' => array_replace($baseRecord['metadata'], ['organisationId' => 'o-created'])],
            ['metric' => 'auth.organisation_invited', 'metadata' => ['plan' => 'pro', 'organisationId' => 'o-invite', 'invitationId' => 'i-invite', 'inviterUserId' => 'u-inviter']],
            ['metric' => 'auth.organisation_invitation_accepted', 'metadata' => ['plan' => 'pro', 'organisationId' => 'o-accepted', 'invitationId' => 'i-accepted', 'inviterUserId' => 'u-inviter', 'userId' => 'u-accepted']],
            ['metric' => 'auth.organisation_invitation_setup', 'metadata' => ['plan' => 'pro', 'organisationId' => 'o-setup', 'invitationId' => 'i-setup', 'inviterUserId' => 'u-inviter', 'userId' => 'u-setup']],
            ['metric' => 'auth.organisation_member_added', 'metadata' => array_replace($baseRecord['metadata'], ['organisationId' => 'o-add', 'userId' => 'u-added'])],
            ['metric' => 'auth.organisation_member_removed', 'metadata' => array_replace($baseRecord['metadata'], ['organisationId' => 'o-remove', 'userId' => 'u-removed'])],
            ['metric' => 'auth.organisation_member_removed', 'metadata' => ['plan' => 'pro', 'organisationId' => 'o-leave', 'userId' => 'u-left']],
        ], $recorded);
    }

    public function testDoesNotRecordExcludedMethodsOrFailedAuthCalls(): void
    {
        $analyticsCalls = 0;
        $recorder = new class($analyticsCalls) {
            public function __construct(private int &$calls)
            {
            }

            public function record(array $body): void
            {
                ++$this->calls;
            }
        };
        $recordAnalytics = ['analytics' => (object) ['events' => $recorder]];
        $client = Client::create('prk_test', 'https://auth.example', static function (string $method, string $url): array {
            $path = (string) parse_url($url, PHP_URL_PATH);
            if ('/api/v1/users' === $path) {
                return ['status' => 422, 'body' => '{"error":"Invalid user.","code":"invalid_user"}'];
            }
            if (str_ends_with($path, '/revoke')) {
                return ['status' => 204, 'body' => ''];
            }

            return ['status' => 200, 'body' => '{"accepted":true,"valid":true,"sessionId":"s1","user":{"id":"u1"}}'];
        });

        try {
            $client->createUser([], ['recordAnalytics' => $recordAnalytics]);
            self::fail('Expected Auth failure.');
        } catch (PartRocksError) {
        }
        $client->refreshSession(['refreshToken' => 'rt']);
        $client->verifySession('jwt');
        $client->requestEmailVerification(['email' => 'a@example.com']);
        $client->requestPasswordReset(['email' => 'a@example.com']);
        $client->revokeOrganisationInvitation('o1', 'revoke', 'jwt');

        self::assertSame(0, $analyticsCalls);
    }

    public function testAnalyticsFailuresFailOpenAndMailRemainsIndependent(): void
    {
        $client = Client::create('prk_test', 'https://auth.example', static function (string $method, string $url): array {
            return str_ends_with($url, '/api/v2/auth/register')
                ? ['status' => 201, 'body' => '{"user":{"id":"u1"},"code":"123456"}']
                : ['status' => 201, 'body' => '{"user":{"id":"u2"},"sessionId":"s2"}'];
        });
        $mailCalls = 0;
        $mail = new class($mailCalls) {
            public function __construct(private int &$calls)
            {
            }

            public function send(array $body): void
            {
                ++$this->calls;
            }
        };
        $quotaRecorder = new class {
            public function record(array $body): array
            {
                return ['recorded' => false, 'code' => 'daily_quota_exceeded'];
            }
        };
        $throwingRecorder = new class {
            public function record(array $body): never
            {
                throw new \RuntimeException('analytics down');
            }
        };

        $quota = $client->register(
            ['email' => 'a@example.com', 'password' => 'password'],
            [
                'sendMail' => ['mail' => $mail, 'application' => 'Acme'],
                'recordAnalytics' => ['analytics' => (object) ['events' => $quotaRecorder]],
            ],
        );
        $thrown = $client->createSession(
            ['username' => 'a@example.com', 'password' => 'password'],
            ['recordAnalytics' => ['analytics' => (object) ['events' => $throwingRecorder]]],
        );
        $failingMail = new class {
            public function send(array $body): never
            {
                throw new \RuntimeException('smtp down');
            }
        };
        $successfulRecorder = new class {
            public function record(array $body): array
            {
                return ['recorded' => true];
            }
        };
        $mailFailure = $client->register(
            ['email' => 'b@example.com', 'password' => 'password'],
            [
                'sendMail' => ['mail' => $failingMail, 'application' => 'Acme'],
                'recordAnalytics' => ['analytics' => (object) ['events' => $successfulRecorder]],
            ],
        );

        self::assertSame(1, $mailCalls);
        self::assertTrue($quota['mailSent']);
        self::assertFalse($quota['analyticsRecorded']);
        self::assertSame('daily_quota_exceeded', $quota['analyticsError']);
        self::assertSame('u1', $quota['user']['id']);
        self::assertFalse($thrown['analyticsRecorded']);
        self::assertSame('analytics down', $thrown['analyticsError']);
        self::assertSame('u2', $thrown['user']['id']);
        self::assertFalse($mailFailure['mailSent']);
        self::assertSame('smtp down', $mailFailure['mailError']);
        self::assertTrue($mailFailure['analyticsRecorded']);
    }

    public function testLogoutWithAnalyticsReturnsAStatusEnvelope(): void
    {
        $client = Client::create('prk_test', 'https://auth.example', fn (): array => ['status' => 204, 'body' => '']);
        $recorder = new class {
            public function record(array $body): array
            {
                return ['recorded' => true];
            }
        };

        $result = $client->logout(['refreshToken' => 'rt'], ['recordAnalytics' => [
            'analytics' => (object) ['events' => $recorder],
            'metadata' => ['userId' => 'u1', 'sessionId' => 's1'],
        ]]);

        self::assertSame(['analyticsRecorded' => true], $result);
    }
}
