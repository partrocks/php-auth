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
     * @param array{sendWelcomeMail?: array{mail: object, application: string, to?: string}}|null $options
     */
    public function createUser(array $body, ?array $options = null): mixed
    {
        $auth = $this->http->request('POST', '/api/v1/users', $body);
        $to = is_string($body['username'] ?? null) ? $body['username'] : '';

        return $this->sendTemplateMail($auth, 'welcome', $to, $options['sendWelcomeMail'] ?? null);
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
     * @return array{token: string, tokenType: string, expiresIn: int, refreshToken: string, refreshExpiresIn: int, sessionId: string, user: array<string, mixed>}
     */
    public function createSession(array $body): mixed
    {
        return $this->http->request('POST', '/api/v1/sessions', $body);
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
     * @param array{sendMail?: array{mail: object, application: string, to?: string}}|null $options
     */
    public function register(array $body, ?array $options = null): mixed
    {
        $auth = $this->http->request('POST', '/api/v2/auth/register', $body);

        return $this->sendTemplateMail($auth, 'verification', $body['email'], $options['sendMail'] ?? null);
    }

    /** @param array{refreshToken: string} $body */
    public function logout(array $body): mixed
    {
        return $this->http->request('POST', '/api/v2/auth/logout', $body);
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
     * @return array{token: string, tokenType: string, expiresIn: int, refreshToken: string, refreshExpiresIn: int, sessionId: string, user: array<string, mixed>}
     */
    public function confirmEmailVerification(array $body): mixed
    {
        return $this->http->request('POST', '/api/v2/auth/email-verifications/confirm', $body);
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

    /** @param array{email: string, code: string, password: string} $body */
    public function confirmPasswordReset(array $body): mixed
    {
        return $this->http->request('POST', '/api/v2/auth/password-resets/confirm', $body);
    }

    public function listOrganisations(string $accessToken): mixed
    {
        return $this->http->request('GET', '/api/v2/organisations', null, $accessToken);
    }

    /** @param array{name: string, slug: string} $body */
    public function createOrganisation(array $body, string $accessToken): mixed
    {
        return $this->http->request('POST', '/api/v2/organisations', $body, $accessToken);
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

    public function leaveOrganisation(string $id, string $accessToken): mixed
    {
        return $this->http->request('DELETE', '/api/v2/organisations/'.$id.'/membership', null, $accessToken);
    }

    public function listOrganisationMembers(string $id, string $accessToken): mixed
    {
        return $this->http->request('GET', '/api/v2/organisations/'.$id.'/members', null, $accessToken);
    }

    /** @param array{userId: string, role?: 'admin'|'user'} $body */
    public function addOrganisationMember(string $id, array $body, string $accessToken): mixed
    {
        return $this->http->request('POST', '/api/v2/organisations/'.$id.'/members', $body, $accessToken);
    }

    /** @param array{role: 'admin'|'user'} $body */
    public function changeOrganisationMemberRole(string $id, string $userId, array $body, string $accessToken): mixed
    {
        return $this->http->request('PATCH', '/api/v2/organisations/'.$id.'/members/'.$userId, $body, $accessToken);
    }

    public function removeOrganisationMember(string $id, string $userId, string $accessToken): mixed
    {
        return $this->http->request('DELETE', '/api/v2/organisations/'.$id.'/members/'.$userId, null, $accessToken);
    }

    public function listOrganisationInvitations(string $id, string $accessToken): mixed
    {
        return $this->http->request('GET', '/api/v2/organisations/'.$id.'/invitations', null, $accessToken);
    }

    /**
     * @param array{email: string} $body
     * @param array{sendMail?: array{mail: object, application: string, to?: string}}|null $options
     */
    public function createOrganisationInvitation(string $id, array $body, string $accessToken, ?array $options = null): mixed
    {
        $auth = $this->http->request('POST', '/api/v2/organisations/'.$id.'/invitations', $body, $accessToken);

        return $this->sendTemplateMail($auth, 'organisation-invitation', $body['email'], $options['sendMail'] ?? null);
    }

    public function revokeOrganisationInvitation(string $id, string $invitationId, string $accessToken): mixed
    {
        return $this->http->request('DELETE', '/api/v2/organisations/'.$id.'/invitations/'.$invitationId, null, $accessToken);
    }

    /**
     * Password-setup path returns a session envelope including sessionId. Bearer accept stays organisation-only.
     *
     * @param array{email: string, code: string, accessToken: string}|array{email: string, code: string, password: string} $options
     * @return mixed
     */
    public function acceptInvitation(array $options): mixed
    {
        if (!isset($options['email'], $options['code']) || !is_string($options['email']) || !is_string($options['code'])) {
            throw new \InvalidArgumentException('acceptInvitation requires email and code.');
        }

        $body = ['email' => $options['email'], 'code' => $options['code']];
        if (isset($options['accessToken']) && is_string($options['accessToken'])) {
            return $this->http->request('POST', '/api/v2/invitations/accept', $body, $options['accessToken']);
        }
        if (isset($options['password']) && is_string($options['password'])) {
            $body['password'] = $options['password'];

            return $this->http->request('POST', '/api/v2/invitations/accept', $body);
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
}
