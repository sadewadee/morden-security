<?php

namespace MordenSecurity\Modules\IPManagement;

use MordenSecurity\Core\LoggerSQLite;
use MordenSecurity\Utils\IPUtils;
use MordenSecurity\Utils\Validation;

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

        if (!$rule || !$rule['is_active']) {
            $result = ['blocked' => false, 'reason' => 'not_blocked'];
        } elseif ($rule['rule_type'] === 'whitelist') {
            $result = ['blocked' => false, 'reason' => 'whitelisted', 'rule' => $rule];
        } elseif ($this->isRuleExpired($rule)) {
            $this->expireRule($rule['id']);
            $result = ['blocked' => false, 'reason' => 'expired'];
        } else {
            $result = [
                'blocked' => true,
                'reason' => $rule['reason'] ?? 'blocked',
                'rule' => $rule,
                'expires_at' => $rule['blocked_until'],
                'block_type' => $rule['rule_type']
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

    public function updateBlockDuration(string $ipAddress, int $newDuration): bool
    {
        if (!IPUtils::isValidIP($ipAddress)) {
            return false;
        }

        try {
            $newBlockedUntil = $newDuration > 0 ? time() + $newDuration : null;

            $stmt = $this->logger->database->prepare('
                UPDATE ms_ip_rules
                SET blocked_until = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE ip_address = ? AND is_active = 1
            ');

            if ($stmt) {
                $stmt->bindValue(1, $newBlockedUntil, SQLITE3_INTEGER);
                $stmt->bindValue(2, $ipAddress, SQLITE3_TEXT);
                $result = $stmt->execute();

                if ($result && $this->logger->database->changes() > 0) {
                    $this->clearCache($ipAddress);
                    return true;
                }
            }
        } catch (Exception $e) {
            error_log("MS: Failed to update block duration for {$ipAddress} - " . $e->getMessage());
        }

        return false;
    }

    public function getBlockedIPs(int $limit = 100, int $offset = 0): array
    {
        try {
            $stmt = $this->logger->database->prepare('
                SELECT * FROM ms_ip_rules
                WHERE rule_type IN ("blacklist", "auto_blocked")
                  AND is_active = 1
                ORDER BY created_at DESC
                LIMIT ? OFFSET ?
            ');

            if (!$stmt) {
                return [];
            }

            $stmt->bindValue(1, $limit, SQLITE3_INTEGER);
            $stmt->bindValue(2, $offset, SQLITE3_INTEGER);

            $result = $stmt->execute();
            $rules = [];

            while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
                $row['is_expired'] = $this->isRuleExpired($row);
                $row['time_remaining'] = $this->getTimeRemaining($row);
                $rules[] = $row;
            }

            return $rules;
        } catch (Exception $e) {
            error_log("MS: Failed to get blocked IPs - " . $e->getMessage());
            return [];
        }
    }

    public function getWhitelistedIPs(): array
    {
        try {
            $stmt = $this->logger->database->prepare('
                SELECT * FROM ms_ip_rules
                WHERE rule_type = "whitelist"
                  AND is_active = 1
                ORDER BY created_at DESC
            ');

            if (!$stmt) {
                return [];
            }

            $result = $stmt->execute();
            $rules = [];

            while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
                $rules[] = $row;
            }

            return $rules;
        } catch (Exception $e) {
            error_log("MS: Failed to get whitelisted IPs - " . $e->getMessage());
            return [];
        }
    }

    public function getBlockStatistics(): array
    {
        $stats = [
            'total_blocked' => 0,
            'temporary_blocks' => 0,
            'permanent_blocks' => 0,
            'auto_blocks' => 0,
            'manual_blocks' => 0,
            'whitelisted' => 0,
            'expired_blocks' => 0
        ];

        try {
            $result = $this->logger->database->query('
                SELECT
                    rule_type,
                    block_duration,
                    block_source,
                    is_active,
                    blocked_until,
                    COUNT(*) as count
                FROM ms_ip_rules
                GROUP BY rule_type, block_duration, block_source, is_active
            ');

            while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
                $count = (int) $row['count'];

                if ($row['rule_type'] === 'whitelist') {
                    $stats['whitelisted'] += $count;
                } elseif ($row['is_active']) {
                    $stats['total_blocked'] += $count;

                    if ($row['block_duration'] === 'temporary') {
                        $stats['temporary_blocks'] += $count;
                    } else {
                        $stats['permanent_blocks'] += $count;
                    }

                    if ($row['block_source'] === 'auto_threat' || $row['block_source'] === 'auto_bot') {
                        $stats['auto_blocks'] += $count;
                    } else {
                        $stats['manual_blocks'] += $count;
                    }
                } else {
                    $stats['expired_blocks'] += $count;
                }
            }
        } catch (Exception $e) {
            error_log("MS: Failed to get block statistics - " . $e->getMessage());
        }

        return $stats;
    }

    public function escalateBlock(string $ipAddress): bool
    {
        $currentRule = $this->logger->getIPRule($ipAddress);
        if (!$currentRule) {
            return false;
        }

        $newEscalationLevel = $currentRule['escalation_count'] + 1;
        $newDuration = $this->calculateBlockDuration('temporary', $newEscalationLevel);

        if ($newEscalationLevel >= 5) {
            return $this->upgradeToPermamentBlock($ipAddress);
        }

        return $this->updateBlockDuration($ipAddress, $newDuration);
    }

    private function getEscalationLevel(string $ipAddress): int
    {
        $rule = $this->logger->getIPRule($ipAddress);
        return $rule ? (int) $rule['escalation_count'] : 0;
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

    private function isRuleExpired(array $rule): bool
    {
        $blockDuration = $rule['block_duration'] ?? 'temporary';
        $blockedUntil = $rule['blocked_until'] ?? null;

        if ($blockDuration === 'permanent' || !$blockedUntil) {
            return false;
        }
        return $blockedUntil < time();
    }

    private function getTimeRemaining(array $rule): int
    {
        if ($rule['block_duration'] === 'permanent' || !$rule['blocked_until']) {
            return -1;
        }

        return max(0, $rule['blocked_until'] - time());
    }

    private function expireRule(int $ruleId): void
    {
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

    private function upgradeToPermamentBlock(string $ipAddress): bool
    {
        try {
            $stmt = $this->logger->database->prepare('
                UPDATE ms_ip_rules
                SET block_duration = "permanent",
                    blocked_until = NULL,
                    escalation_count = escalation_count + 1,
                    updated_at = CURRENT_TIMESTAMP,
                    notes = COALESCE(notes, "") || " - Escalated to permanent"
                WHERE ip_address = ? AND is_active = 1
            ');

            if ($stmt) {
                $stmt->bindValue(1, $ipAddress, SQLITE3_TEXT);
                $result = $stmt->execute();

                if ($result && $this->logger->database->changes() > 0) {
                    $this->clearCache($ipAddress);
                    $this->logBlockAction($ipAddress, ['escalation' => 'permanent'], 'escalated');
                    return true;
                }
            }
        } catch (Exception $e) {
            error_log("MS: Failed to upgrade to permanent block for {$ipAddress} - " . $e->getMessage());
        }

        return false;
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
