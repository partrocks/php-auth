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
    public static function create(string $baseUrl, string $apiKey, ?callable $transport = null): self
    {
        return new self(new Http(rtrim($baseUrl, '/'), $apiKey, $transport));
    }

    public function listUsers(): mixed
    {
        return $this->http->request('GET', '/api/v1/users');
    }

    /** @param array<string, mixed> $body */
    public function createUser(array $body): mixed
    {
        return $this->http->request('POST', '/api/v1/users', $body);
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

    public function deleteUser(string $id): mixed
    {
        return $this->http->request('DELETE', '/api/v1/users/'.$id);
    }

    /** @param array{username: string, password: string} $body */
    public function createSession(array $body): mixed
    {
        return $this->http->request('POST', '/api/v1/sessions', $body);
    }

    /** @param array{refreshToken: string} $body */
    public function refreshSession(array $body): mixed
    {
        return $this->http->request('POST', '/api/v1/sessions/refresh', $body);
    }

    public function verifySession(string $accessToken): mixed
    {
        return $this->http->request('POST', '/api/v1/sessions/verify', null, $accessToken);
    }

    /** @param array{email: string, password: string} $body */
    public function register(array $body): mixed
    {
        return $this->http->request('POST', '/api/v2/auth/register', $body);
    }

    /** @param array{refreshToken: string} $body */
    public function logout(array $body): mixed
    {
        return $this->http->request('POST', '/api/v2/auth/logout', $body);
    }

    public function requestEmailVerification(string $accessToken): mixed
    {
        return $this->http->request('POST', '/api/v2/auth/email-verifications/request', null, $accessToken);
    }

    public function acceptEmailVerification(string $token, string $accessToken): mixed
    {
        return $this->http->request('POST', '/api/v2/auth/email-verifications/'.$token.'/accept', null, $accessToken);
    }

    /** @param array{email: string} $body */
    public function requestPasswordReset(array $body): mixed
    {
        return $this->http->request('POST', '/api/v2/auth/password-resets/request', $body);
    }

    /** @param array{password: string} $body */
    public function acceptPasswordReset(string $token, array $body): mixed
    {
        return $this->http->request('POST', '/api/v2/auth/password-resets/'.$token.'/accept', $body);
    }

    public function listTeams(string $accessToken): mixed
    {
        return $this->http->request('GET', '/api/v2/teams', null, $accessToken);
    }

    /** @param array{name: string, slug: string} $body */
    public function createTeam(array $body, string $accessToken): mixed
    {
        return $this->http->request('POST', '/api/v2/teams', $body, $accessToken);
    }

    public function getTeam(string $id, string $accessToken): mixed
    {
        return $this->http->request('GET', '/api/v2/teams/'.$id, null, $accessToken);
    }

    /** @param array{name?: string, slug?: string} $body */
    public function updateTeam(string $id, array $body, string $accessToken): mixed
    {
        return $this->http->request('PATCH', '/api/v2/teams/'.$id, $body, $accessToken);
    }

    public function deleteTeam(string $id, string $accessToken): mixed
    {
        return $this->http->request('DELETE', '/api/v2/teams/'.$id, null, $accessToken);
    }

    public function teamMembership(string $id, string $accessToken): mixed
    {
        return $this->http->request('GET', '/api/v2/teams/'.$id.'/membership', null, $accessToken);
    }

    public function listMembers(string $id, string $accessToken): mixed
    {
        return $this->http->request('GET', '/api/v2/teams/'.$id.'/members', null, $accessToken);
    }

    /** @param array{userId: string, role?: string} $body */
    public function addMember(string $id, array $body, string $accessToken): mixed
    {
        return $this->http->request('POST', '/api/v2/teams/'.$id.'/members', $body, $accessToken);
    }

    /** @param array{role: string} $body */
    public function updateMember(string $id, string $userId, array $body, string $accessToken): mixed
    {
        return $this->http->request('PATCH', '/api/v2/teams/'.$id.'/members/'.$userId, $body, $accessToken);
    }

    public function removeMember(string $id, string $userId, string $accessToken): mixed
    {
        return $this->http->request('DELETE', '/api/v2/teams/'.$id.'/members/'.$userId, null, $accessToken);
    }

    public function listInvitations(string $id, string $accessToken): mixed
    {
        return $this->http->request('GET', '/api/v2/teams/'.$id.'/invitations', null, $accessToken);
    }

    /** @param array{email: string} $body */
    public function createInvitation(string $id, array $body, string $accessToken): mixed
    {
        return $this->http->request('POST', '/api/v2/teams/'.$id.'/invitations', $body, $accessToken);
    }

    public function revokeInvitation(string $id, string $invitationId, string $accessToken): mixed
    {
        return $this->http->request('DELETE', '/api/v2/teams/'.$id.'/invitations/'.$invitationId, null, $accessToken);
    }

    public function acceptInvitation(string $token, string $accessToken): mixed
    {
        return $this->http->request('POST', '/api/v2/invitations/'.$token.'/accept', null, $accessToken);
    }
}
