<?php

namespace MordenSecurity\Modules\Login;

use MordenSecurity\Core\LoggerSQLite;

if (!defined('ABSPATH')) {
    exit;
}

class RateLimiter
{
    private LoggerSQLite $logger;
    private string $cachePrefix = 'ms_rate_limit_';

    public function __construct(LoggerSQLite $logger)
    {
        $this->logger = $logger;
    }

    public function checkRateLimit(string $identifier, string $action, int $maxAttempts, int $timeWindow): array
    {
        $attempts = $this->getAttemptCount($identifier, $action, $timeWindow);
        $lockoutTime = $this->getLockoutTime($identifier, $action);

        if ($lockoutTime > time()) {
            return [
                'allowed' => false,
                'reason' => 'locked_out',
                'attempts' => $attempts,
                'max_attempts' => $maxAttempts,
                'lockout_until' => $lockoutTime,
                'time_remaining' => $lockoutTime - time()
            ];
        }

        if ($attempts >= $maxAttempts) {
            return [
                'allowed' => false,
                'reason' => 'rate_limited',
                'attempts' => $attempts,
                'max_attempts' => $maxAttempts
            ];
        }

        return [
            'allowed' => true,
            'attempts' => $attempts,
            'max_attempts' => $maxAttempts,
            'remaining_attempts' => $maxAttempts - $attempts
        ];
    }

    public function recordAttempt(string $identifier, string $action): void
    {
        $cacheKey = $this->getCacheKey($identifier, $action);
        $attempts = get_transient($cacheKey) ?: [];

        $attempts[] = time();

        $attempts = array_filter($attempts, fn($time) => $time > (time() - 3600));

        set_transient($cacheKey, $attempts, 3600);

        $this->logger->logSecurityEvent([
            'event_type' => 'rate_limit_attempt',
            'severity' => 1,
            'ip_address' => $identifier,
            'message' => "Rate limit attempt recorded for {$action}",
            'context' => [
                'identifier' => $identifier,
                'action' => $action,
                'attempt_count' => count($attempts)
            ],
            'action_taken' => 'logged'
        ]);
    }

    public function getAttemptCount(string $identifier, string $action, int $timeWindow): int
    {
        $cacheKey = $this->getCacheKey($identifier, $action);
        $attempts = get_transient($cacheKey) ?: [];

        $cutoffTime = time() - $timeWindow;
        $validAttempts = array_filter($attempts, fn($time) => $time > $cutoffTime);

        return count($validAttempts);
    }

    public function setLockout(string $identifier, string $action, int $duration): void
    {
        $lockoutKey = $this->getLockoutKey($identifier, $action);
        $lockoutUntil = time() + $duration;

        set_transient($lockoutKey, $lockoutUntil, $duration);

        $this->logger->logSecurityEvent([
            'event_type' => 'rate_limit_lockout',
            'severity' => 2,
            'ip_address' => $identifier,
            'message' => "Lockout set for {$action}",
            'context' => [
                'identifier' => $identifier,
                'action' => $action,
                'duration' => $duration,
                'lockout_until' => $lockoutUntil
            ],
            'action_taken' => 'lockout_set'
        ]);
    }

    public function getLockoutTime(string $identifier, string $action): int
    {
        $lockoutKey = $this->getLockoutKey($identifier, $action);
        return (int) get_transient($lockoutKey);
    }

    public function clearAttempts(string $identifier, string $action): void
    {
        $cacheKey = $this->getCacheKey($identifier, $action);
        $lockoutKey = $this->getLockoutKey($identifier, $action);

        delete_transient($cacheKey);
        delete_transient($lockoutKey);
    }

    public function isBlocked(string $identifier, string $action): bool
    {
        $lockoutTime = $this->getLockoutTime($identifier, $action);
        return $lockoutTime > time();
    }

    public function getTimeRemaining(string $identifier, string $action): int
    {
        $lockoutTime = $this->getLockoutTime($identifier, $action);
        return max(0, $lockoutTime - time());
    }

    public function extendLockout(string $identifier, string $action, int $additionalTime): void
    {
        $currentLockout = $this->getLockoutTime($identifier, $action);
        $newLockout = max($currentLockout, time()) + $additionalTime;

        $lockoutKey = $this->getLockoutKey($identifier, $action);
        set_transient($lockoutKey, $newLockout, $newLockout - time());
    }

    public function getRateLimitStatus(string $identifier, string $action = null): array
    {
        if ($action) {
            return [
                'identifier' => $identifier,
                'action' => $action,
                'attempts_1h' => $this->getAttemptCount($identifier, $action, 3600),
                'attempts_24h' => $this->getAttemptCount($identifier, $action, 86400),
                'is_blocked' => $this->isBlocked($identifier, $action),
                'lockout_until' => $this->getLockoutTime($identifier, $action),
                'time_remaining' => $this->getTimeRemaining($identifier, $action)
            ];
        }

        $actions = ['login', 'comment', 'contact', 'registration'];
        $status = ['identifier' => $identifier, 'actions' => []];

        foreach ($actions as $actionType) {
            $status['actions'][$actionType] = [
                'attempts_1h' => $this->getAttemptCount($identifier, $actionType, 3600),
                'is_blocked' => $this->isBlocked($identifier, $actionType),
                'lockout_until' => $this->getLockoutTime($identifier, $actionType)
            ];
        }

        return $status;
    }

    private function getCacheKey(string $identifier, string $action): string
    {
        return $this->cachePrefix . 'attempts_' . md5($identifier . '_' . $action);
    }

    private function getLockoutKey(string $identifier, string $action): string
    {
        return $this->cachePrefix . 'lockout_' . md5($identifier . '_' . $action);
    }
}
