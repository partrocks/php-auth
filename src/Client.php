<?php

declare(strict_types=1);

namespace PartRocks\Auth;

final class Client
{
    public function __construct(private readonly Http $http)
    {
    }

    /**
     * @param null|callable(string, string, array<string, string>, ?string): array{status: int, body: string} $transport
     */
    public static function create(string $apiKey, ?string $baseUrl = null, ?callable $transport = null): self
    {
        $trimmed = null === $baseUrl ? '' : trim($baseUrl);
        $origin = '' === $trimmed ? 'https://auth.part.rocks' : $trimmed;

        return new self(new Http(rtrim($origin, '/'), $apiKey, $transport));
    }

    public function listUsers(): mixed
    {
        return $this->http->request('GET', '/api/v1/users');
    }

    /**
     * @param array<string, mixed> $body
     * @param array{
     *   sendWelcomeMail?: array{mail: object, application: string, to?: string},
     *   recordAnalytics?: array{analytics: object, metadata?: array<string, string|int|float|bool>}
     * }|null $options
     */
    public function createUser(array $body, ?array $options = null): mixed
    {
        $auth = $this->http->request('POST', '/api/v1/users', $body);
        $to = is_string($body['username'] ?? null) ? $body['username'] : '';
        $withMail = $this->sendTemplateMail($auth, 'welcome', $to, $options['sendWelcomeMail'] ?? null);

        return $this->recordAnalytics($withMail, 'auth.user_created', array_filter([
            'userId' => $this->stringAt($auth, 'user', 'id'),
            'source' => 'operator',
        ], static fn (mixed $value): bool => null !== $value), $options['recordAnalytics'] ?? null);
    }

    public function getUser(string $id): mixed
    {
        return $this->http->request('GET', '/api/v1/users/'.$id);
    }

    /** @param array<string, mixed> $body */
    public function updateUser(string $id, array $body): mixed
    {
        return $this->http->request('PATCH', '/api/v1/users/'.$id, $body);
    }

    /**
     * Auth returns 409 `final_admin` with `organisations: [{ id, name }]` when the user is the last admin of any organisation.
     */
    public function deleteUser(string $id): mixed
    {
        return $this->http->request('DELETE', '/api/v1/users/'.$id);
    }

    /**
     * @param array{username: string, password: string} $body
     * @param array{recordAnalytics?: array{analytics: object, metadata?: array<string, string|int|float|bool>}}|null $options
     * @return array{token: string, tokenType: string, expiresIn: int, refreshToken: string, refreshExpiresIn: int, sessionId: string, user: array<string, mixed>}
     */
    public function createSession(array $body, ?array $options = null): mixed
    {
        $auth = $this->http->request('POST', '/api/v1/sessions', $body);

        return $this->recordAnalytics($auth, 'auth.login', array_filter([
            'userId' => $this->stringAt($auth, 'user', 'id'),
            'sessionId' => $this->stringAt($auth, 'sessionId'),
        ], static fn (mixed $value): bool => null !== $value), $options['recordAnalytics'] ?? null);
    }

    /**
     * @param array{refreshToken: string} $body
     * @return array{token: string, tokenType: string, expiresIn: int, refreshToken: string, refreshExpiresIn: int, sessionId: string, user: array<string, mixed>}
     */
    public function refreshSession(array $body): mixed
    {
        return $this->http->request('POST', '/api/v1/sessions/refresh', $body);
    }

    /**
     * @return array{valid: bool, expiresAt: string, sessionId?: string, user: array<string, mixed>}
     */
    public function verifySession(string $accessToken): mixed
    {
        return $this->http->request('POST', '/api/v1/sessions/verify', null, $accessToken);
    }

    /**
     * @param array{email: string, password: string} $body
     * @param array{
     *   sendMail?: array{mail: object, application: string, to?: string},
     *   recordAnalytics?: array{analytics: object, metadata?: array<string, string|int|float|bool>}
     * }|null $options
     */
    public function register(array $body, ?array $options = null): mixed
    {
        $auth = $this->http->request('POST', '/api/v2/auth/register', $body);
        $withMail = $this->sendTemplateMail($auth, 'verification', $body['email'], $options['sendMail'] ?? null);

        return $this->recordAnalytics($withMail, 'auth.user_created', array_filter([
            'userId' => $this->stringAt($auth, 'user', 'id'),
            'source' => 'register',
        ], static fn (mixed $value): bool => null !== $value), $options['recordAnalytics'] ?? null);
    }

    /**
     * @param array{refreshToken: string} $body
     * @param array{recordAnalytics?: array{analytics: object, metadata?: array<string, string|int|float|bool>}}|null $options
     */
    public function logout(array $body, ?array $options = null): mixed
    {
        $auth = $this->http->request('POST', '/api/v2/auth/logout', $body);

        return $this->recordAnalytics($auth, 'auth.logout', [], $options['recordAnalytics'] ?? null);
    }

    /**
     * @param array{email: string} $body
     * @param array{sendMail?: array{mail: object, application: string, to?: string}}|null $options
     */
    public function requestEmailVerification(array $body, ?array $options = null): mixed
    {
        $auth = $this->http->request('POST', '/api/v2/auth/email-verifications/request', $body);

        return $this->sendTemplateMail($auth, 'verification', $body['email'], $options['sendMail'] ?? null);
    }

    /**
     * @param array{email: string, code: string} $body
     * @param array{recordAnalytics?: array{analytics: object, metadata?: array<string, string|int|float|bool>}}|null $options
     * @return array{token: string, tokenType: string, expiresIn: int, refreshToken: string, refreshExpiresIn: int, sessionId: string, user: array<string, mixed>}
     */
    public function confirmEmailVerification(array $body, ?array $options = null): mixed
    {
        $auth = $this->http->request('POST', '/api/v2/auth/email-verifications/confirm', $body);

        return $this->recordAnalytics($auth, 'auth.email_verified', array_filter([
            'userId' => $this->stringAt($auth, 'user', 'id'),
        ], static fn (mixed $value): bool => null !== $value), $options['recordAnalytics'] ?? null);
    }

    /**
     * @param array{email: string} $body
     * @param array{sendMail?: array{mail: object, application: string, to?: string}}|null $options
     */
    public function requestPasswordReset(array $body, ?array $options = null): mixed
    {
        $auth = $this->http->request('POST', '/api/v2/auth/password-resets/request', $body);

        return $this->sendTemplateMail($auth, 'password-reset', $body['email'], $options['sendMail'] ?? null);
    }

    /**
     * @param array{email: string, code: string, password: string} $body
     * @param array{recordAnalytics?: array{analytics: object, metadata?: array<string, string|int|float|bool>}}|null $options
     */
    public function confirmPasswordReset(array $body, ?array $options = null): mixed
    {
        $auth = $this->http->request('POST', '/api/v2/auth/password-resets/confirm', $body);

        return $this->recordAnalytics($auth, 'auth.password_reset_completed', [], $options['recordAnalytics'] ?? null);
    }

    public function listOrganisations(string $accessToken): mixed
    {
        return $this->http->request('GET', '/api/v2/organisations', null, $accessToken);
    }

    /**
     * @param array{name: string, slug: string} $body
     * @param array{recordAnalytics?: array{analytics: object, metadata?: array<string, string|int|float|bool>}}|null $options
     */
    public function createOrganisation(array $body, string $accessToken, ?array $options = null): mixed
    {
        $auth = $this->http->request('POST', '/api/v2/organisations', $body, $accessToken);

        return $this->recordAnalytics($auth, 'auth.organisation_created', array_filter([
            'organisationId' => $this->stringAt($auth, 'organisation', 'id'),
        ], static fn (mixed $value): bool => null !== $value), $options['recordAnalytics'] ?? null);
    }

    public function getOrganisation(string $id, string $accessToken): mixed
    {
        return $this->http->request('GET', '/api/v2/organisations/'.$id, null, $accessToken);
    }

    /** @param array{name?: string, slug?: string} $body */
    public function updateOrganisation(string $id, array $body, string $accessToken): mixed
    {
        return $this->http->request('PATCH', '/api/v2/organisations/'.$id, $body, $accessToken);
    }

    public function deleteOrganisation(string $id, string $accessToken): mixed
    {
        return $this->http->request('DELETE', '/api/v2/organisations/'.$id, null, $accessToken);
    }

    public function getCurrentOrganisationMembership(string $id, string $accessToken): mixed
    {
        return $this->http->request('GET', '/api/v2/organisations/'.$id.'/membership', null, $accessToken);
    }

    /** @param array{recordAnalytics?: array{analytics: object, metadata?: array<string, string|int|float|bool>}}|null $options */
    public function leaveOrganisation(string $id, string $accessToken, ?array $options = null): mixed
    {
        $auth = $this->http->request('DELETE', '/api/v2/organisations/'.$id.'/membership', null, $accessToken);

        return $this->recordAnalytics($auth, 'auth.organisation_member_removed', [
            'organisationId' => $id,
        ], $options['recordAnalytics'] ?? null);
    }

    public function listOrganisationMembers(string $id, string $accessToken): mixed
    {
        return $this->http->request('GET', '/api/v2/organisations/'.$id.'/members', null, $accessToken);
    }

    /**
     * @param array{userId: string, role?: 'admin'|'user'} $body
     * @param array{recordAnalytics?: array{analytics: object, metadata?: array<string, string|int|float|bool>}}|null $options
     */
    public function addOrganisationMember(string $id, array $body, string $accessToken, ?array $options = null): mixed
    {
        $auth = $this->http->request('POST', '/api/v2/organisations/'.$id.'/members', $body, $accessToken);

        return $this->recordAnalytics($auth, 'auth.organisation_member_added', [
            'organisationId' => $id,
            'userId' => $this->stringAt($auth, 'member', 'userId') ?? $body['userId'],
        ], $options['recordAnalytics'] ?? null);
    }

    /** @param array{role: 'admin'|'user'} $body */
    public function changeOrganisationMemberRole(string $id, string $userId, array $body, string $accessToken): mixed
    {
        return $this->http->request('PATCH', '/api/v2/organisations/'.$id.'/members/'.$userId, $body, $accessToken);
    }

    /** @param array{recordAnalytics?: array{analytics: object, metadata?: array<string, string|int|float|bool>}}|null $options */
    public function removeOrganisationMember(string $id, string $userId, string $accessToken, ?array $options = null): mixed
    {
        $auth = $this->http->request('DELETE', '/api/v2/organisations/'.$id.'/members/'.$userId, null, $accessToken);

        return $this->recordAnalytics($auth, 'auth.organisation_member_removed', [
            'organisationId' => $id,
            'userId' => $userId,
        ], $options['recordAnalytics'] ?? null);
    }

    public function listOrganisationInvitations(string $id, string $accessToken): mixed
    {
        return $this->http->request('GET', '/api/v2/organisations/'.$id.'/invitations', null, $accessToken);
    }

    /**
     * @param array{email: string} $body
     * @param array{
     *   sendMail?: array{mail: object, application: string, to?: string},
     *   recordAnalytics?: array{analytics: object, metadata?: array<string, string|int|float|bool>}
     * }|null $options
     */
    public function createOrganisationInvitation(string $id, array $body, string $accessToken, ?array $options = null): mixed
    {
        $auth = $this->http->request('POST', '/api/v2/organisations/'.$id.'/invitations', $body, $accessToken);
        $withMail = $this->sendTemplateMail($auth, 'organisation-invitation', $body['email'], $options['sendMail'] ?? null);

        return $this->recordAnalytics($withMail, 'auth.organisation_invited', [
            'organisationId' => $id,
        ], $options['recordAnalytics'] ?? null);
    }

    public function revokeOrganisationInvitation(string $id, string $invitationId, string $accessToken): mixed
    {
        return $this->http->request('DELETE', '/api/v2/organisations/'.$id.'/invitations/'.$invitationId, null, $accessToken);
    }

    /**
     * Password-setup path returns a session envelope including sessionId. Bearer accept stays organisation-only.
     *
     * @param array{email: string, code: string, accessToken: string, recordAnalytics?: array{analytics: object, metadata?: array<string, string|int|float|bool>}}|array{email: string, code: string, password: string, recordAnalytics?: array{analytics: object, metadata?: array<string, string|int|float|bool>}} $options
     * @return mixed
     */
    public function acceptInvitation(array $options): mixed
    {
        if (!isset($options['email'], $options['code']) || !is_string($options['email']) || !is_string($options['code'])) {
            throw new \InvalidArgumentException('acceptInvitation requires email and code.');
        }

        $body = ['email' => $options['email'], 'code' => $options['code']];
        if (isset($options['accessToken']) && is_string($options['accessToken'])) {
            $auth = $this->http->request('POST', '/api/v2/invitations/accept', $body, $options['accessToken']);

            return $this->recordAnalytics($auth, 'auth.organisation_invitation_accepted', array_filter([
                'organisationId' => $this->stringAt($auth, 'organisation', 'id'),
                'userId' => $this->stringAt($auth, 'user', 'id'),
            ], static fn (mixed $value): bool => null !== $value), $options['recordAnalytics'] ?? null);
        }
        if (isset($options['password']) && is_string($options['password'])) {
            $body['password'] = $options['password'];
            $auth = $this->http->request('POST', '/api/v2/invitations/accept', $body);

            return $this->recordAnalytics($auth, 'auth.organisation_invitation_setup', array_filter([
                'organisationId' => $this->stringAt($auth, 'organisation', 'id'),
                'userId' => $this->stringAt($auth, 'user', 'id'),
            ], static fn (mixed $value): bool => null !== $value), $options['recordAnalytics'] ?? null);
        }

        throw new \InvalidArgumentException('acceptInvitation requires accessToken or password.');
    }

    /**
     * @param array{mail: object, application: string, to?: string}|null $options
     */
    private function sendTemplateMail(mixed $auth, string $template, string $fallbackTo, ?array $options): mixed
    {
        if (null === $options) {
            return $auth;
        }

        $payload = is_array($auth) ? $auth : ['auth' => $auth];
        $to = is_string($options['to'] ?? null) ? $options['to'] : $fallbackTo;
        $code = is_string($payload['code'] ?? null) ? $payload['code'] : '';
        if ('' === $to || ('welcome' !== $template && '' === $code)) {
            return $payload;
        }

        $metadata = ['application' => $options['application']];
        if ('' !== $code) {
            $metadata['code'] = $code;
        }
        if ('welcome' === $template) {
            $metadata['username'] = $to;
        }

        try {
            $this->invokeMailSend($options['mail'], [
                'to' => $to,
                'template' => $template,
                'metadata' => $metadata,
            ]);
            $payload['mailSent'] = true;
        } catch (\Throwable $error) {
            $payload['mailSent'] = false;
            $payload['mailError'] = $error->getMessage();
        }

        return $payload;
    }

    /** @param array<string, mixed> $body */
    private function invokeMailSend(object $mail, array $body): mixed
    {
        if (isset($mail->messages) && is_object($mail->messages) && method_exists($mail->messages, 'send')) {
            return $mail->messages->send($body);
        }
        if (method_exists($mail, 'send')) {
            return $mail->send($body);
        }

        throw new \InvalidArgumentException('mail must provide send().');
    }

    /**
     * @param array<string, string|int|float|bool> $requiredMetadata
     * @param array{analytics: object, metadata?: array<string, string|int|float|bool>}|null $options
     */
    private function recordAnalytics(mixed $auth, string $metric, array $requiredMetadata, ?array $options): mixed
    {
        if (null === $options) {
            return $auth;
        }

        $payload = is_array($auth) ? $auth : (null === $auth ? [] : ['auth' => $auth]);
        $metadata = array_replace($options['metadata'] ?? [], $requiredMetadata);

        try {
            $result = $this->invokeAnalyticsRecord($options['analytics'], [
                'metric' => $metric,
                'metadata' => $metadata,
            ]);
            if (is_array($result) && false === ($result['recorded'] ?? null)) {
                $payload['analyticsRecorded'] = false;
                $payload['analyticsError'] = is_string($result['code'] ?? null) && '' !== $result['code']
                    ? $result['code']
                    : 'Analytics event was not recorded.';

                return $payload;
            }

            $payload['analyticsRecorded'] = true;
        } catch (\Throwable $error) {
            $payload['analyticsRecorded'] = false;
            $payload['analyticsError'] = '' !== $error->getMessage()
                ? $error->getMessage()
                : 'Analytics recording failed.';
        }

        return $payload;
    }

    /** @param array<string, mixed> $body */
    private function invokeAnalyticsRecord(object $analytics, array $body): mixed
    {
        if (isset($analytics->events) && is_object($analytics->events) && method_exists($analytics->events, 'record')) {
            return $analytics->events->record($body);
        }
        if (method_exists($analytics, 'recordEvent')) {
            return $analytics->recordEvent($body);
        }

        throw new \InvalidArgumentException('analytics must provide events.record().');
    }

    private function stringAt(mixed $value, string ...$path): ?string
    {
        foreach ($path as $key) {
            if (!is_array($value) || !array_key_exists($key, $value)) {
                return null;
            }
            $value = $value[$key];
        }

        return is_string($value) && '' !== $value ? $value : null;
    }
}
