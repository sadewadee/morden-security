<?php

namespace MordenSecurity\Core;

use MordenSecurity\Modules\WAF\WAFRules;
use MordenSecurity\Utils\IPUtils;
use MordenSecurity\Core\LoggerSQLite;

class Firewall {
    private $logger;
    private $wafEngine;
    private $config;

    public function __construct($logger, $wafEngine) {
        $this->logger = $logger;
        $this->wafEngine = $wafEngine;
        $this->config = [
            'firewall_enabled' => get_option('ms_firewall_enabled', true),
            'threat_threshold' => get_option('ms_threat_threshold', 7),
            'challenge_threshold' => get_option('ms_challenge_threshold', 5)
        ];
    }

    public function checkRequest(): array {
        if (!$this->config['firewall_enabled']) {
            return ['action' => 'allow', 'reason' => 'firewall_disabled'];
        }

        // Gunakan WAF engine untuk semua deteksi
        $requestData = $this->gatherRequestData();
        $wafResult = $this->wafEngine->evaluateRequest($requestData);

        if (empty($wafResult)) {
            return ['action' => 'allow', 'reason' => 'no_threats'];
        }

        // Analisis hasil dari WAF
        $analysis = $this->analyzeThreats($wafResult);
        $this->logFirewallEvent($analysis);

        return $analysis;
    }

    private function gatherRequestData(): array {
        return [
            'uri' => $_SERVER['REQUEST_URI'] ?? '',
            'query_string' => $_SERVER['QUERY_STRING'] ?? '',
            'post_data' => http_build_query($_POST ?? []),
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
            'headers' => $this->getSecurityHeaders(),
            'method' => $_SERVER['REQUEST_METHOD'] ?? 'GET',
            'referer' => $_SERVER['HTTP_REFERER'] ?? ''
        ];
    }

    private function analyzeThreats(array $violations): array {
        $highestSeverity = max(array_column($violations, 'severity'));
        $criticalThreats = array_filter($violations, fn($v) => $v['severity'] >= $this->config['threat_threshold']);
        $suspiciousThreats = array_filter($violations, fn($v) => $v['severity'] >= $this->config['challenge_threshold']);

        $action = 'allow';
        $reason = 'low_threat';

        if (!empty($criticalThreats)) {
            $action = 'block';
            $reason = $criticalThreats[0]['rule_group'] . '_violation';
        } elseif (!empty($suspiciousThreats)) {
            $action = 'challenge';
            $reason = 'suspicious_activity';
        }

        return [
            'action' => $action,
            'reason' => $reason,
            'severity' => $highestSeverity,
            'violations' => $violations,
            'threat_categories' => $this->categorizeThreats($violations)
        ];
    }

    private function categorizeThreats(array $violations): array {
        $categories = [];
        foreach ($violations as $violation) {
            $category = $violation['rule_group'] ?? 'unknown';
            if (!isset($categories[$category])) {
                $categories[$category] = 0;
            }
            $categories[$category]++;
        }
        return $categories;
    }

    private function getSecurityHeaders(): array {
        return [
            'accept' => $_SERVER['HTTP_ACCEPT'] ?? '',
            'accept_language' => $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? '',
            'accept_encoding' => $_SERVER['HTTP_ACCEPT_ENCODING'] ?? '',
            'x_forwarded_for' => $_SERVER['HTTP_X_FORWARDED_FOR'] ?? '',
            'x_real_ip' => $_SERVER['HTTP_X_REAL_IP'] ?? ''
        ];
    }

    private function logFirewallEvent(array $analysis): void {
        if ($analysis['action'] !== 'allow') {
            $this->logger->logSecurityEvent([
                'event_type' => 'firewall_' . $analysis['action'],
                'severity' => $analysis['severity'],
                'ip_address' => IPUtils::getRealClientIP(),
                'message' => "Firewall {$analysis['action']}: {$analysis['reason']}",
                'context' => [
                    'violations' => $analysis['violations'],
                    'threat_categories' => $analysis['threat_categories']
                ],
                'action_taken' => $analysis['action'],
                'threat_score' => $analysis['severity']
            ]);
        }
    }
}
