<?php

namespace MordenSecurity\Modules\IPManagement;

use MordenSecurity\Core\LoggerSQLite;
use MordenSecurity\Utils\IPUtils;

if (!defined('ABSPATH')) {
    exit;
}

class BlockingEngine
{
    private LoggerSQLite $logger;
    private IPBlocker $ipBlocker;
    private CountryBlocker $countryBlocker;
    private array $config;

    public function __construct(LoggerSQLite $logger)
    {
        $this->logger = $logger;
        $this->ipBlocker = new IPBlocker($logger);
        $this->countryBlocker = new CountryBlocker($logger);
        $this->config = [
            'blocking_enabled' => get_option('ms_blocking_enabled', true),
            'block_order' => get_option('ms_block_order', ['whitelist', 'blacklist', 'country', 'auto']),
            'graceful_blocking' => get_option('ms_graceful_blocking', true)
        ];
    }

    public function evaluateRequest(string $ipAddress): array
    {
        if (!$this->config['blocking_enabled']) {
            return $this->createResult('allow', 'blocking_disabled');
        }

        if (IPUtils::isPrivateIP($ipAddress)) {
            return $this->createResult('allow', 'private_ip');
        }

        foreach ($this->config['block_order'] as $blockType) {
            $result = $this->evaluateBlockType($blockType, $ipAddress);

            if ($result['action'] !== 'continue') {
                $this->logBlockingDecision($ipAddress, $blockType, $result);
                return $result;
            }
        }

        return $this->createResult('allow', 'no_blocks_matched');
    }

    public function processBlockRequest(string $ipAddress, array $blockData): array
    {
        $result = $this->evaluateRequest($ipAddress);

        if ($result['action'] === 'block') {
            return $this->executeBlock($ipAddress, $blockData, $result);
        }

        return $this->createResult('allow', 'evaluation_passed');
    }

    public function executeBlock(string $ipAddress, array $blockData, array $evaluation): array
    {
        $blockResult = [
            'blocked' => false,
            'method' => 'none',
            'message' => '',
            'evaluation' => $evaluation
        ];

        if ($this->config['graceful_blocking']) {
            $blockResult = $this->executeGracefulBlock($ipAddress, $blockData);
        } else {
            $blockResult = $this->executeImmediateBlock($ipAddress, $blockData);
        }

        $this->logBlockExecution($ipAddress, $blockResult);
        return $blockResult;
    }

    public function unblockIP(string $ipAddress, string $reason = 'manual_unblock'): bool
    {
        $success = false;

        $ipSuccess = $this->ipBlocker->removeBlock($ipAddress);
        if ($ipSuccess) {
            $success = true;
        }

        $this->logger->logSecurityEvent([
            'event_type' => 'ip_unblocked',
            'severity' => 2,
            'ip_address' => $ipAddress,
            'message' => "IP unblocked: {$reason}",
            'context' => [
                'reason' => $reason,
                'unblock_method' => 'blocking_engine',
                'success' => $success
            ],
            'action_taken' => $success ? 'ip_unblocked' : 'unblock_failed'
        ]);

        return $success;
    }

    public function getBlockingStatistics(): array
    {
        $stats = [
            'total_blocks' => 0,
            'ip_blocks' => 0,
            'country_blocks' => 0,
            'auto_blocks' => 0,
            'block_methods' => [],
            'top_blocked_ips' => [],
            'block_reasons' => []
        ];

        $events = $this->logger->getRecentEvents(5000, [
            'event_type' => 'request_blocked'
        ]);

        foreach ($events as $event) {
            $stats['total_blocks']++;

            $context = json_decode($event['context'], true) ?? [];
            $blockReason = $context['block_reason'] ?? 'unknown';

            if (!isset($stats['block_reasons'][$blockReason])) {
                $stats['block_reasons'][$blockReason] = 0;
            }
            $stats['block_reasons'][$blockReason]++;

            if (strpos($blockReason, 'ip') !== false) {
                $stats['ip_blocks']++;
            } elseif (strpos($blockReason, 'country') !== false) {
                $stats['country_blocks']++;
            } elseif (strpos($blockReason, 'auto') !== false) {
                $stats['auto_blocks']++;
            }

            $ip = $event['ip_address'];
            if (!isset($stats['top_blocked_ips'][$ip])) {
                $stats['top_blocked_ips'][$ip] = 0;
            }
            $stats['top_blocked_ips'][$ip]++;
        }

        arsort($stats['top_blocked_ips']);
        $stats['top_blocked_ips'] = array_slice($stats['top_blocked_ips'], 0, 10, true);

        return $stats;
    }

    public function optimizeBlocking(): array
    {
        $optimizations = [];

        $expiredBlocks = $this->cleanupExpiredBlocks();
        if ($expiredBlocks > 0) {
            $optimizations[] = "Cleaned up {$expiredBlocks} expired blocks";
        }

        $duplicateRules = $this->removeDuplicateRules();
        if ($duplicateRules > 0) {
            $optimizations[] = "Removed {$duplicateRules} duplicate rules";
        }

        $consolidatedRanges = $this->consolidateIPRanges();
        if ($consolidatedRanges > 0) {
            $optimizations[] = "Consolidated {$consolidatedRanges} IP ranges";
        }

        return $optimizations;
    }

    private function evaluateBlockType(string $blockType, string $ipAddress): array
    {
        switch ($blockType) {
            case 'whitelist':
                return $this->evaluateWhitelist($ipAddress);

            case 'blacklist':
                return $this->evaluateBlacklist($ipAddress);

            case 'country':
                return $this->evaluateCountryBlock($ipAddress);

            case 'auto':
                return $this->evaluateAutoBlock($ipAddress);

            default:
                return $this->createResult('continue', 'unknown_block_type');
        }
    }

    private function evaluateWhitelist(string $ipAddress): array
    {
        $rule = $this->logger->getIPRule($ipAddress);

        if ($rule && $rule['rule_type'] === 'whitelist' && $rule['is_active']) {
            return $this->createResult('allow', 'whitelisted', $rule);
        }

        return $this->createResult('continue', 'not_whitelisted');
    }

    private function evaluateBlacklist(string $ipAddress): array
    {
        $rule = $this->logger->getIPRule($ipAddress);

        if ($rule && $rule['rule_type'] === 'blacklist' && $rule['is_active']) {
            if ($rule['blocked_until'] && $rule['blocked_until'] < time()) {
                return $this->createResult('continue', 'blacklist_expired');
            }
            return $this->createResult('block', 'blacklisted', $rule);
        }

        return $this->createResult('continue', 'not_blacklisted');
    }

    private function evaluateCountryBlock(string $ipAddress): array
    {
        $countryCheck = $this->countryBlocker->checkCountryAccess($ipAddress);

        if (!$countryCheck['allowed']) {
            return $this->createResult('block', $countryCheck['reason'], $countryCheck);
        }

        return $this->createResult('continue', 'country_allowed');
    }

    private function evaluateAutoBlock(string $ipAddress): array
    {
        $rule = $this->logger->getIPRule($ipAddress);

        if ($rule && $rule['rule_type'] === 'auto_blocked' && $rule['is_active']) {
            if ($rule['blocked_until'] && $rule['blocked_until'] < time()) {
                return $this->createResult('continue', 'auto_block_expired');
            }
            return $this->createResult('block', 'auto_blocked', $rule);
        }

        return $this->createResult('continue', 'not_auto_blocked');
    }

    private function executeGracefulBlock(string $ipAddress, array $blockData): array
    {
        $gracePeriod = get_option('ms_grace_period', 300);

        $warningResult = $this->sendBlockWarning($ipAddress, $gracePeriod);
        if ($warningResult['sent']) {
            sleep(min($gracePeriod, 5));
        }

        return $this->executeImmediateBlock($ipAddress, $blockData);
    }

    private function executeImmediateBlock(string $ipAddress, array $blockData): array
    {
        $success = $this->ipBlocker->addBlock($ipAddress, $blockData);

        if ($success) {
            $this->sendBlockNotification($ipAddress, $blockData);
        }

        return [
            'blocked' => $success,
            'method' => 'immediate',
            'message' => $success ? 'IP blocked successfully' : 'Failed to block IP',
            'block_data' => $blockData
        ];
    }

    private function sendBlockWarning(string $ipAddress, int $gracePeriod): array
    {
        return ['sent' => false, 'reason' => 'warnings_disabled'];
    }

    private function sendBlockNotification(string $ipAddress, array $blockData): void
    {
        do_action('ms_ip_blocked', $ipAddress, $blockData);
    }

    private function cleanupExpiredBlocks(): int
    {
        try {
            $stmt = $this->logger->database->prepare('
                UPDATE ms_ip_rules
                SET is_active = 0
                WHERE blocked_until IS NOT NULL
                  AND blocked_until < ?
                  AND is_active = 1
            ');

            if ($stmt) {
                $stmt->bindValue(1, time(), SQLITE3_INTEGER);
                $result = $stmt->execute();
                return $result ? $this->logger->database->changes() : 0;
            }
        } catch (Exception $e) {
            error_log("MS: Failed to cleanup expired blocks - " . $e->getMessage());
        }

        return 0;
    }

    private function removeDuplicateRules(): int
    {
        return 0;
    }

    private function consolidateIPRanges(): int
    {
        return 0;
    }

    private function createResult(string $action, string $reason, array $data = []): array
    {
        return [
            'action' => $action,
            'reason' => $reason,
            'data' => $data,
            'timestamp' => time()
        ];
    }

    private function logBlockingDecision(string $ipAddress, string $blockType, array $result): void
    {
        if ($result['action'] === 'block') {
            $this->logger->logSecurityEvent([
                'event_type' => 'blocking_decision',
                'severity' => 2,
                'ip_address' => $ipAddress,
                'message' => "Blocking decision: {$result['action']} ({$result['reason']})",
                'context' => [
                    'block_type' => $blockType,
                    'decision' => $result,
                    'engine' => 'blocking_engine'
                ],
                'action_taken' => 'blocking_evaluated'
            ]);
        }
    }

    private function logBlockExecution(string $ipAddress, array $blockResult): void
    {
        $this->logger->logSecurityEvent([
            'event_type' => 'block_execution',
            'severity' => $blockResult['blocked'] ? 3 : 2,
            'ip_address' => $ipAddress,
            'message' => "Block execution: {$blockResult['message']}",
            'context' => [
                'block_result' => $blockResult,
                'engine' => 'blocking_engine'
            ],
            'action_taken' => $blockResult['blocked'] ? 'ip_blocked' : 'block_failed'
        ]);
    }
}
