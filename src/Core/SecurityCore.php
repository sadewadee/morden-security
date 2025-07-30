<?php

namespace MordenSecurity\Core;

use MordenSecurity\Utils\IPUtils;
use MordenSecurity\Modules\WAF\WAFRules;

if (!defined('ABSPATH')) {
    exit;
}

class SecurityCore
{
    private LoggerSQLite $logger;
    private AutoIPBlocker $autoBlocker;
    private BotDetection $botDetection;
    private Firewall $firewall;
    private bool $initialized = false;

    public function __construct()
    {
        $this->logger = new LoggerSQLite();
        $this->autoBlocker = new AutoIPBlocker($this->logger);
        $this->botDetection = new BotDetection($this->logger);
        $this->firewall = new Firewall($this->logger);
    }

    public function initialize(): void
    {
        if ($this->initialized) {
            return;
        }

        $this->registerHooks();
        $this->scheduleMaintenanceTasks();
        $this->initialized = true;
    }

    public function interceptRequest(): void
    {
        if (!$this->initialized) {
            return;
        }

        $ipAddress = IPUtils::getRealClientIP();
        $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
        $requestUri = $_SERVER['REQUEST_URI'] ?? '';

        $ipEvaluation = $this->autoBlocker->evaluateIPThreat($ipAddress);

        if ($ipEvaluation['action'] === 'block') {
            $this->blockRequest($ipAddress, $ipEvaluation['reason']);
            return;
        }

        $botAnalysis = $this->botDetection->analyzeRequest();

        if ($botAnalysis['action'] === 'block') {
            $this->blockRequest($ipAddress, 'malicious_bot_detected');
            return;
        }

        if ($botAnalysis['action'] === 'challenge') {
            $this->challengeRequest($ipAddress, 'suspicious_bot_behavior');
            return;
        }

        $firewallResult = $this->firewall->checkRequest();

        if ($firewallResult['action'] === 'block') {
            $this->blockRequest($ipAddress, $firewallResult['reason']);
            return;
        }

        $this->logAllowedRequest($ipAddress, $userAgent, $requestUri);
    }

    public function blockRequest(string $ipAddress, string $reason): void
    {
        $this->logger->logSecurityEvent([
            'event_type' => 'request_blocked',
            'severity' => 3,
            'ip_address' => $ipAddress,
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
            'request_uri' => $_SERVER['REQUEST_URI'] ?? '',
            'message' => "Request blocked: {$reason}",
            'context' => [
                'block_reason' => $reason,
                'request_method' => $_SERVER['REQUEST_METHOD'] ?? '',
                'referer' => $_SERVER['HTTP_REFERER'] ?? ''
            ],
            'action_taken' => 'request_blocked',
            'blocked_reason' => $reason
        ]);

        $this->sendBlockedResponse($reason);
    }

    public function challengeRequest(string $ipAddress, string $reason): void
    {
        $this->logger->logSecurityEvent([
            'event_type' => 'request_challenged',
            'severity' => 2,
            'ip_address' => $ipAddress,
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
            'request_uri' => $_SERVER['REQUEST_URI'] ?? '',
            'message' => "Request challenged: {$reason}",
            'context' => [
                'challenge_reason' => $reason,
                'request_method' => $_SERVER['REQUEST_METHOD'] ?? ''
            ],
            'action_taken' => 'request_challenged'
        ]);

        $this->sendChallengeResponse($reason);
    }

    public function logAllowedRequest(string $ipAddress, string $userAgent, string $requestUri): void
    {
        if (get_option('ms_log_allowed_requests', false)) {
            $this->logger->logSecurityEvent([
                'event_type' => 'request_allowed',
                'severity' => 1,
                'ip_address' => $ipAddress,
                'user_agent' => $userAgent,
                'request_uri' => $requestUri,
                'message' => 'Request allowed',
                'action_taken' => 'request_allowed'
            ]);
        }
    }

    public function getSecurityStatus(): array
    {
        $recentEvents = $this->logger->getRecentEvents(100);
        $blockedCount = count(array_filter($recentEvents, fn($e) => $e['event_type'] === 'request_blocked'));

        return [
            'status' => 'active',
            'total_events' => count($recentEvents),
            'blocked_requests' => $blockedCount,
            'allowed_requests' => count($recentEvents) - $blockedCount,
            'threat_level' => $this->calculateThreatLevel($recentEvents),
            'last_update' => time()
        ];
    }

    private function registerHooks(): void
    {
        add_action('init', [$this, 'interceptRequest'], 1);
        add_action('ms_cleanup_temp_blocks', [$this->autoBlocker, 'cleanupExpiredBlocks']);
        add_action('wp_login_failed', [$this, 'handleFailedLogin']);
        add_action('xmlrpc_call', [$this, 'handleXMLRPCRequest']);
    }

    private function scheduleMaintenanceTasks(): void
    {
        if (!wp_next_scheduled('ms_cleanup_temp_blocks')) {
            wp_schedule_event(time(), 'hourly', 'ms_cleanup_temp_blocks');
        }
    }

    private function sendBlockedResponse(string $reason): void
    {
        if (!headers_sent()) {
            status_header(403);
            header('Content-Type: text/html; charset=UTF-8');
            header('X-Security-Block: morden-security');
        }

        $title = __('Access Denied', 'morden-security');
        $message = __('Your request has been blocked by our security system.', 'morden-security');

        echo $this->generateBlockPage($title, $message, $reason);
        exit;
    }

    private function sendChallengeResponse(string $reason): void
    {
        if (!headers_sent()) {
            status_header(429);
            header('Content-Type: text/html; charset=UTF-8');
            header('X-Security-Challenge: morden-security');
            header('Retry-After: 60');
        }

        $title = __('Security Challenge', 'morden-security');
        $message = __('Please wait a moment while we verify your request.', 'morden-security');

        echo $this->generateChallengePage($title, $message);
        exit;
    }

    private function generateBlockPage(string $title, string $message, string $reason): string
    {
        return "<!DOCTYPE html>
<html>
<head>
    <title>{$title}</title>
    <meta charset='UTF-8'>
    <style>
        body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
        .container { max-width: 500px; margin: 0 auto; }
        .error-code { font-size: 72px; color: #dc3545; font-weight: bold; }
        .message { font-size: 18px; color: #666; margin: 20px 0; }
        .reason { font-size: 14px; color: #999; font-style: italic; }
    </style>
</head>
<body>
    <div class='container'>
        <div class='error-code'>403</div>
        <h1>{$title}</h1>
        <p class='message'>{$message}</p>
        <p class='reason'>Reason: {$reason}</p>
    </div>
</body>
</html>";
    }

    private function generateChallengePage(string $title, string $message): string
    {
        return "<!DOCTYPE html>
<html>
<head>
    <title>{$title}</title>
    <meta charset='UTF-8'>
    <meta http-equiv='refresh' content='5'>
    <style>
        body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
        .container { max-width: 500px; margin: 0 auto; }
        .spinner { border: 4px solid #f3f3f3; border-top: 4px solid #007cba;
                   border-radius: 50%; width: 50px; height: 50px;
                   animation: spin 1s linear infinite; margin: 20px auto; }
        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
    </style>
</head>
<body>
    <div class='container'>
        <h1>{$title}</h1>
        <div class='spinner'></div>
        <p>{$message}</p>
    </div>
</body>
</html>";
    }

    private function calculateThreatLevel(array $events): string
    {
        $recentThreats = array_filter($events, function($event) {
            return $event['timestamp'] > time() - 3600 &&
                   in_array($event['event_type'], ['request_blocked', 'bot_detected', 'firewall_block']);
        });

        $threatCount = count($recentThreats);

        if ($threatCount > 50) return 'critical';
        if ($threatCount > 20) return 'high';
        if ($threatCount > 5) return 'medium';
        return 'low';
    }

    public function handleFailedLogin(string $username): void
    {
        $ipAddress = IPUtils::getRealClientIP();

        $this->logger->logSecurityEvent([
            'event_type' => 'login_failed',
            'severity' => 2,
            'ip_address' => $ipAddress,
            'message' => "Failed login attempt for user: {$username}",
            'context' => ['username' => $username],
            'action_taken' => 'logged'
        ]);

        $this->autoBlocker->escalateThreat($ipAddress);
    }

    public function handleXMLRPCRequest(string $method): void
    {
        $ipAddress = IPUtils::getRealClientIP();

        $this->logger->logSecurityEvent([
            'event_type' => 'xmlrpc_request',
            'severity' => 2,
            'ip_address' => $ipAddress,
            'message' => "XML-RPC request: {$method}",
            'context' => ['method' => $method],
            'action_taken' => 'monitored'
        ]);
    }
}
