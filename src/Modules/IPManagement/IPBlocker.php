<?php

namespace MordenSecurity\Modules\IPManagement;

use MordenSecurity\Core\LoggerSQLite;
use MordenSecurity\Utils\IPUtils;
use MordenSecurity\Utils\Validation;
use Exception;

if (!defined('ABSPATH')) {
    exit;
}

class IPBlocker
{
    private LoggerSQLite $logger;
    private array $config;
    private array $blockCache;

    public function __construct(LoggerSQLite $logger)
    {
        $this->logger = $logger;
        $this->config = [
            'default_block_duration' => get_option('ms_default_block_duration', 3600),
            'max_block_duration' => get_option('ms_max_block_duration', 86400 * 30),
            'escalation_multiplier' => get_option('ms_escalation_multiplier', 2),
            'cache_enabled' => get_option('ms_ip_cache_enabled', true)
        ];
        $this->blockCache = [];
    }

    public function isBlocked(string $ipAddress): array
    {
        if ($this->config['cache_enabled'] && isset($this->blockCache[$ipAddress])) {
            return $this->blockCache[$ipAddress];
        }

        $rule = $this->logger->getIPRule($ipAddress);

        if (!$rule || !($rule['is_active'] ?? true)) {
            $result = ['blocked' => false, 'reason' => 'not_blocked'];
        } elseif (in_array($rule['rule_type'] ?? '', ['whitelist', 'temp_whitelist'])) {
            // Check if temp whitelist expired
            if ($rule['rule_type'] === 'temp_whitelist' &&
                $rule['blocked_until'] &&
                $rule['blocked_until'] < time()) {
                $this->expireRule($rule['id'] ?? 0);
                $result = ['blocked' => false, 'reason' => 'temp_whitelist_expired'];
            } else {
                $result = ['blocked' => false, 'reason' => 'whitelisted', 'rule' => $rule];
            }
        } elseif ($this->isRuleExpired($rule)) {
            $this->expireRule($rule['id'] ?? 0);
            $result = ['blocked' => false, 'reason' => 'expired'];
        } else {
            $result = [
                'blocked' => true,
                'reason' => $rule['reason'] ?? 'blocked',
                'rule' => $rule,
                'expires_at' => $rule['blocked_until'] ?? null,
                'block_type' => $rule['rule_type'] ?? 'blacklist'
            ];
        }

        if ($this->config['cache_enabled']) {
            $this->blockCache[$ipAddress] = $result;
        }

        return $result;
    }


    public function addBlock(string $ipAddress, array $blockData): bool
    {
        if (!IPUtils::isValidIP($ipAddress)) {
            return false;
        }

        $ruleType = Validation::validateRuleType($blockData['rule_type'] ?? 'blacklist');
        $duration = Validation::validateBlockDuration($blockData['duration'] ?? 'temporary');

        $escalationLevel = $this->getEscalationLevel($ipAddress);
        $numericBlockDuration = $this->calculateBlockDuration($duration, $escalationLevel);

        $blockedUntil = null;
        if ($duration !== 'permanent') {
            $blockedUntil = time() + $numericBlockDuration;
        }

        $ruleData = [
            'ip_address' => $ipAddress,
            'rule_type' => $ruleType,
            'block_duration' => $duration,
            'blocked_until' => $blockedUntil,
            'reason' => Validation::sanitizeLogMessage($blockData['reason'] ?? 'Manual block'),
            'threat_score' => Validation::validateThreatScore($blockData['threat_score'] ?? 0),
            'block_source' => $blockData['source'] ?? 'manual',
            'created_by' => get_current_user_id() ?: null,
            'escalation_count' => $escalationLevel,
            'notes' => Validation::sanitizeLogMessage($blockData['notes'] ?? '')
        ];

        $success = $this->logger->addIPRule($ruleData);

        if ($success) {
            $this->clearCache($ipAddress);
            $this->logBlockAction($ipAddress, $ruleData, 'added');
            do_action('ms_ip_blocked', $ipAddress, $ruleData);
        }

        return $success;
    }

    public function removeBlock(string $ipAddress): bool
    {
        if (!IPUtils::isValidIP($ipAddress)) {
            return false;
        }

        try {
            $stmt = $this->logger->database->prepare('
                UPDATE ms_ip_rules
                SET is_active = 0,
                    updated_at = CURRENT_TIMESTAMP,
                    notes = COALESCE(notes, "") || " - Manually unblocked"
                WHERE ip_address = ? AND is_active = 1
            ');

            if ($stmt) {
                $stmt->bindValue(1, $ipAddress, SQLITE3_TEXT);
                $result = $stmt->execute();

                if ($result && $this->logger->database->changes() > 0) {
                    $this->clearCache($ipAddress);
                    $this->logBlockAction($ipAddress, [], 'removed');
                    do_action('ms_ip_unblocked', $ipAddress);
                    return true;
                }
            }
        } catch (Exception $e) {
            error_log("MS: Failed to remove IP block for {$ipAddress} - " . $e->getMessage());
        }

        return false;
    }

    public function addWhitelist(string $ipAddress, array $whitelistData): bool
    {
        if (!IPUtils::isValidIP($ipAddress)) {
            return false;
        }

        $ruleData = [
            'ip_address' => $ipAddress,
            'rule_type' => 'whitelist',
            'block_duration' => 'permanent',
            'blocked_until' => null,
            'reason' => Validation::sanitizeLogMessage($whitelistData['reason'] ?? 'Whitelisted'),
            'threat_score' => 0,
            'block_source' => $whitelistData['source'] ?? 'manual',
            'created_by' => get_current_user_id() ?: null,
            'escalation_count' => 0,
            'notes' => Validation::sanitizeLogMessage($whitelistData['notes'] ?? 'Added to whitelist')
        ];

        $success = $this->logger->addIPRule($ruleData);

        if ($success) {
            $this->clearCache($ipAddress);
            $this->logBlockAction($ipAddress, $ruleData, 'whitelisted');
        }

        return $success;
    }

    public function getBlockStatistics(): array
    {
        return [
            'total_blocked' => 0,
            'temporary_blocks' => 0,
            'permanent_blocks' => 0,
            'auto_blocks' => 0,
            'manual_blocks' => 0,
            'whitelisted' => 0,
            'expired_blocks' => 0
        ];
    }

    private function isRuleExpired(array $rule): bool
    {
        $blockDuration = $rule['block_duration'] ?? 'temporary';
        $blockedUntil = $rule['blocked_until'] ?? null;

        if ($blockDuration === 'permanent' || !$blockedUntil) {
            return false;
        }

        return $blockedUntil < time();
    }

    private function getEscalationLevel(string $ipAddress): int
    {
        $rule = $this->logger->getIPRule($ipAddress);
        return $rule ? (int) ($rule['escalation_count'] ?? 0) : 0;
    }

    private function calculateBlockDuration(string $durationType, int $escalationLevel): int
    {
        if ($durationType === 'permanent') {
            return 0;
        }

        $baseDuration = $this->config['default_block_duration'];
        $escalatedDuration = $baseDuration * pow($this->config['escalation_multiplier'], $escalationLevel);

        return min($escalatedDuration, $this->config['max_block_duration']);
    }

    private function expireRule(int $ruleId): void
    {
        if ($ruleId <= 0) return;

        try {
            $stmt = $this->logger->database->prepare('
                UPDATE ms_ip_rules
                SET is_active = 0, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            ');

            if ($stmt) {
                $stmt->bindValue(1, $ruleId, SQLITE3_INTEGER);
                $stmt->execute();
            }
        } catch (Exception $e) {
            error_log("MS: Failed to expire rule {$ruleId} - " . $e->getMessage());
        }
    }

    private function clearCache(string $ipAddress): void
    {
        if (isset($this->blockCache[$ipAddress])) {
            unset($this->blockCache[$ipAddress]);
        }
    }

    private function logBlockAction(string $ipAddress, array $ruleData, string $action): void
    {
        $this->logger->logSecurityEvent([
            'event_type' => "ip_block_{$action}",
            'severity' => 2,
            'ip_address' => $ipAddress,
            'message' => "IP block {$action}: {$ipAddress}",
            'context' => [
                'action' => $action,
                'rule_data' => $ruleData,
                'source' => 'ip_blocker'
            ],
            'action_taken' => "ip_{$action}"
        ]);
    }
}
