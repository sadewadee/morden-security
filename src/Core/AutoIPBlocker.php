<?php

namespace MordenSecurity\Core;

use MordenSecurity\Utils\IPUtils;

if (!defined('ABSPATH')) {
    exit;
}

class AutoIPBlocker
{
    private LoggerSQLite $logger;
    private array $config;
    private array $threatThresholds;

    public function __construct(LoggerSQLite $logger)
    {
        $this->logger = $logger;
        $this->config = [
            'auto_blocking_enabled' => get_option('ms_auto_blocking_enabled', true),
            'temp_block_duration' => get_option('ms_temp_block_duration', 3600),
            'perm_block_threshold' => get_option('ms_perm_block_threshold', 5),
            'escalation_multiplier' => get_option('ms_escalation_multiplier', 2)
        ];

        $this->threatThresholds = [
            'low' => 50,
            'medium' => 100,
            'high' => 200,
            'critical' => 500
        ];
    }

    public function evaluateIPThreat(string $ipAddress): array
    {
        if (IPUtils::isPrivateIP($ipAddress)) {
            return ['action' => 'allow', 'reason' => 'private_ip'];
        }

        $existingRule = $this->logger->getIPRule($ipAddress);
        if ($existingRule) {
            return $this->handleExistingRule($existingRule);
        }

        $threatScore = $this->calculateThreatScore($ipAddress);
        $geoData = IPUtils::getIPGeolocation($ipAddress);

        return $this->determineAction($ipAddress, $threatScore, $geoData);
    }

    public function blockIP(string $ipAddress, string $reason, string $duration = 'temporary', int $escalationLevel = 0): bool
    {
        $blockData = [
            'ip_address' => $ipAddress,
            'rule_type' => 'auto_blocked',
            'block_duration' => $duration,
            'blocked_until' => $duration === 'temporary' ? time() + $this->calculateBlockDuration($escalationLevel) : null,
            'reason' => $reason,
            'threat_score' => $this->logger->getIPThreatScore($ipAddress),
            'block_source' => 'auto_threat',
            'escalation_count' => $escalationLevel,
            'notes' => "Auto-blocked: {$reason}"
        ];

        $success = $this->logger->addIPRule($blockData);

        if ($success) {
            $this->logger->logSecurityEvent([
                'event_type' => 'ip_auto_blocked',
                'severity' => $this->getSeverityFromDuration($duration),
                'ip_address' => $ipAddress,
                'message' => "IP automatically blocked: {$reason}",
                'context' => [
                    'block_duration' => $duration,
                    'escalation_level' => $escalationLevel,
                    'threat_score' => $blockData['threat_score']
                ],
                'action_taken' => 'ip_blocked',
                'blocked_reason' => $reason
            ]);
        }

        return $success;
    }

    public function escalateThreat(string $ipAddress): bool
    {
        $existingRule = $this->logger->getIPRule($ipAddress);
        if (!$existingRule) {
            return $this->blockIP($ipAddress, 'threat_escalation', 'temporary', 1);
        }

        $newEscalationLevel = $existingRule['escalation_count'] + 1;

        if ($newEscalationLevel >= $this->config['perm_block_threshold']) {
            return $this->blockIP($ipAddress, 'escalation_threshold_reached', 'permanent', $newEscalationLevel);
        }

        return $this->blockIP($ipAddress, 'threat_escalation', 'temporary', $newEscalationLevel);
    }

    public function cleanupExpiredBlocks(): int
    {
        if (!$this->logger) {
            return 0;
        }

        $currentTime = time();
        $cleanupCount = 0;

        try {
            $stmt = $this->logger->database->prepare('
                UPDATE ms_ip_rules
                SET is_active = 0
                WHERE blocked_until IS NOT NULL
                  AND blocked_until < ?
                  AND is_active = 1
            ');

            if ($stmt) {
                $stmt->bindValue(1, $currentTime, SQLITE3_INTEGER);
                $result = $stmt->execute();

                if ($result) {
                    $cleanupCount = $this->logger->database->changes();
                }
            }
        } catch (Exception $e) {
            error_log("MS: Failed to cleanup expired blocks - " . $e->getMessage());
        }

        return $cleanupCount;
    }

    private function handleExistingRule(array $rule): array
    {
        if ($rule['rule_type'] === 'whitelist') {
            return ['action' => 'allow', 'reason' => 'whitelisted'];
        }

        if ($rule['rule_type'] === 'blacklist' || $rule['rule_type'] === 'auto_blocked') {
            if ($rule['blocked_until'] && $rule['blocked_until'] < time()) {
                return ['action' => 'allow', 'reason' => 'block_expired'];
            }
            return ['action' => 'block', 'reason' => $rule['reason'] ?? 'previously_blocked'];
        }

        return ['action' => 'allow', 'reason' => 'unknown_rule'];
    }

    private function calculateThreatScore(string $ipAddress): int
    {
        $recentScore = $this->logger->getIPThreatScore($ipAddress, 3600);
        $dailyScore = $this->logger->getIPThreatScore($ipAddress, 86400);

        return $recentScore + ($dailyScore * 0.3);
    }

    private function determineAction(string $ipAddress, int $threatScore, array $geoData): array
    {
        if (!$this->config['auto_blocking_enabled']) {
            return ['action' => 'allow', 'reason' => 'auto_blocking_disabled'];
        }

        if ($threatScore >= $this->threatThresholds['critical']) {
            $this->blockIP($ipAddress, 'critical_threat_score', 'permanent');
            return ['action' => 'block', 'reason' => 'critical_threat'];
        }

        if ($threatScore >= $this->threatThresholds['high']) {
            $this->blockIP($ipAddress, 'high_threat_score', 'temporary', 2);
            return ['action' => 'block', 'reason' => 'high_threat'];
        }

        if ($threatScore >= $this->threatThresholds['medium']) {
            $this->blockIP($ipAddress, 'medium_threat_score', 'temporary', 1);
            return ['action' => 'block', 'reason' => 'medium_threat'];
        }

        return ['action' => 'allow', 'reason' => 'low_threat'];
    }

    private function calculateBlockDuration(int $escalationLevel): int
    {
        $baseTimeout = $this->config['temp_block_duration'];
        return $baseTimeout * pow($this->config['escalation_multiplier'], $escalationLevel);
    }

    private function getSeverityFromDuration(string $duration): int
    {
        return $duration === 'permanent' ? 4 : 3;
    }
}
