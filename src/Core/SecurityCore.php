<?php

namespace MordenSecurity\Core;

use MordenSecurity\Modules\WAF\WAFRules;
use MordenSecurity\Modules\WAF\CustomRules;
use MordenSecurity\Modules\WAF\RulesetManager;
use MordenSecurity\Core\LoggerSQLite;
use MordenSecurity\Core\BotDetection;
use MordenSecurity\Core\Firewall;
use MordenSecurity\Core\GeoDetection;
use MordenSecurity\Modules\IPManagement\BlockingEngine;
use MordenSecurity\Modules\Login\LoginProtection;
use MordenSecurity\Utils\IPUtils;

if (!defined('ABSPATH')) {
    exit;
}

class SecurityCore {
    private $logger;
    private $wafEngine;
    private $firewall;
    private $botDetection;
    private $autoIPBlocker;
    private $geoDetection;
    private $loginProtection;
    private $initialized = false;
    private $requestIntercepted = false;

    public function __construct() {
        $this->logger = new LoggerSQLite();
        $this->geoDetection = new GeoDetection();

        // Initialize WAF components
        $rulesetManager = new RulesetManager($this->logger);
        $customRules = new CustomRules($this->logger);
        $this->wafEngine = new WAFRules($this->logger, $rulesetManager, $customRules);

        // Initialize other components
        $this->firewall = new Firewall($this->logger, $this->wafEngine);
        $this->botDetection = new BotDetection($this->logger);
        $this->blockingEngine = new BlockingEngine($this->logger);
        $this->loginProtection = new LoginProtection($this->logger);
    }

    public function getSecurityStatus(): array
    {
        $stats = $this->logger->getSecurityStats();

        return [
            'overall_status' => $this->determineOverallStatus($stats),
            'threat_level' => $stats['threat_level'] ?? 'low',
            'security_enabled' => $this->isSecurityEnabled(),
            'total_events' => $stats['total_events'] ?? 0,
            'blocked_requests' => $stats['blocked_requests'] ?? 0,
            'bot_detections' => $stats['bot_detections'] ?? 0,
            'firewall_blocks' => $stats['firewall_blocks'] ?? 0,
            'active_rules' => $this->getActiveRulesCount(),
            'last_threat' => $this->getLastThreatTime(),
            'uptime' => $this->getSecurityUptime()
        ];
    }

    public function initialize(): void
    {
        if ($this->initialized) {
            return;
        }

        add_action('init', [$this, 'earlySecurityChecks'], 1);
        add_action('rest_api_init', [$this, 'interceptRequest'], 1);
        add_action('template_redirect', [$this, 'interceptRequest'], 1);

        $this->initialized = true;
    }

    public function interceptRequest(): ?array {
        if ($this->requestIntercepted || !$this->isSecurityEnabled()) {
            return null;
        }
        $this->requestIntercepted = true;

        $ipAddress = IPUtils::getRealClientIP();

        $firewallResult = $this->firewall->checkRequest();
        if ($firewallResult['action'] === 'block') {
            $this->logSecurityEvent(
                $firewallResult['event_type'] ?? 'waf_blocked',
                $ipAddress,
                $firewallResult
            );
            $this->blockRequest('Access Denied - Security Rule Violation');
            return $firewallResult;
        }

        if ($this->isLoggedInAdmin()) {
            $this->ensureAdminWhitelisted($ipAddress);
            return null;
        }

        $botAnalysis = $this->botDetection->analyzeRequest();
        if ($botAnalysis['is_bot'] && $botAnalysis['action'] === 'block') {
            $this->logSecurityEvent(
                $botAnalysis['event_type'] ?? 'bad_bot_detected',
                $ipAddress,
                $botAnalysis
            );
            $this->blockRequest('Access Denied - Malicious Bot Detected');
            return $botAnalysis;
        }

        $ipCheck = $this->blockingEngine->evaluateRequest($ipAddress);
        if ($ipCheck['action'] === 'block') {
            $this->logSecurityEvent('ip_blocked', $ipAddress, $ipCheck);
            $this->blockRequest('Access Denied - IP Blocked');
            return $ipCheck;
        }

        $this->logRequest($ipAddress);
        return null;
    }

    private function logRequest(string $ipAddress): void
    {
        $this->logSecurityEvent('traffic', $ipAddress, ['action' => 'log', 'severity' => 1, 'impact' => 0], 200);
    }

    public function earlySecurityChecks(): void
    {
        $this->preventDirectAccess();
        $this->checkMaintenanceMode();
    }

    private function determineOverallStatus(array $stats): string
    {
        $threatLevel = $stats['threat_level'] ?? 'low';
        $isEnabled = $this->isSecurityEnabled();

        if (!$isEnabled) {
            return 'disabled';
        }

        switch ($threatLevel) {
            case 'critical':
                return 'critical';
            case 'high':
                return 'warning';
            case 'medium':
                return 'active';
            default:
                return 'secure';
        }
    }

    private function getActiveRulesCount(): int
    {
        try {
            $result = $this->logger->database->query('
                SELECT COUNT(*) as count FROM ms_ip_rules
                WHERE is_active = 1
            ');

            $row = $result->fetchArray(SQLITE3_ASSOC);
            return (int) ($row['count'] ?? 0);

        } catch (Exception $e) {
            return 0;
        }
    }

    private function getLastThreatTime(): ?int
    {
        try {
            $result = $this->logger->database->query('
                SELECT timestamp FROM ms_security_events
                WHERE severity >= 3
                ORDER BY timestamp DESC
                LIMIT 1
            ');

            $row = $result->fetchArray(SQLITE3_ASSOC);
            return $row ? (int) $row['timestamp'] : null;

        } catch (Exception $e) {
            return null;
        }
    }

    private function getSecurityUptime(): int
    {
        $startTime = get_option('ms_security_start_time', time());
        return time() - $startTime;
    }

    private function isSecurityEnabled(): bool
    {
        return get_option('ms_security_enabled', true);
    }

    private function isLoggedInAdmin(): bool
    {
        return is_user_logged_in() && current_user_can('administrator');
    }

    private function ensureAdminWhitelisted(string $ipAddress): void
    {
        $existingRule = $this->logger->getIPRule($ipAddress);

        if (!$existingRule ||
            $existingRule['rule_type'] !== 'temp_whitelist' ||
            ($existingRule['blocked_until'] && $existingRule['blocked_until'] < time())) {

            $currentUser = wp_get_current_user();
            $whitelistData = [
                'ip_address' => $ipAddress,
                'rule_type' => 'temp_whitelist',
                'block_duration' => 'temporary',
                'blocked_until' => time() + (24 * 3600),
                'reason' => "Active admin session: {$currentUser->user_login}",
                'threat_score' => 0,
                'block_source' => 'admin_session',
                'created_by' => $currentUser->ID,
                'escalation_count' => 0,
                'notes' => 'Admin session whitelist - 24 hours'
            ];

            $this->logger->addIPRule($whitelistData);
        }
    }

    private function logSecurityEvent(string $eventType, string $ipAddress, array $context, int $httpCode = 403): void
    {
        $context['request_method'] = $_SERVER['REQUEST_METHOD'] ?? 'N/A';
        $context['http_code'] = $httpCode;
        $currentUser = wp_get_current_user();
        if ($currentUser->ID !== 0) {
            $context['username'] = $currentUser->user_login;
        }

        $this->logger->logSecurityEvent([
            'event_type' => $eventType,
            'severity' => $context['severity'] ?? 3,
            'ip_address' => $ipAddress,
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
            'request_uri' => $_SERVER['REQUEST_URI'] ?? '',
            'message' => $context['reason'] ?? "Security event: {$eventType}",
            'context' => $context,
            'action_taken' => $context['action'] ?? 'blocked',
            'country_code' => $this->geoDetection->getLocationData($ipAddress)['country_code'],
            'threat_score' => $context['impact'] ?? 0,
        ]);
    }

    private function blockRequest(string $message): void
    {
        http_response_code(403);
        header('Content-Type: text/plain');
        echo $message;
        exit;
    }

    private function preventDirectAccess(): void
    {
        if (!defined('ABSPATH')) {
            http_response_code(403);
            exit('Direct access forbidden.');
        }
    }

    private function checkMaintenanceMode(): void
    {
        if (get_option('ms_maintenance_mode', false) && !current_user_can('administrator')) {
            wp_die(__('Site temporarily unavailable for maintenance.', 'morden-security'));
        }
    }

    public function getBotDetectionStats(): array
    {
        return $this->logger->getBotDetectionStats();
    }
}
