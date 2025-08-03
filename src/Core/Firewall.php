<?php

namespace MordenSecurity\Core;

use MordenSecurity\Modules\WAF\WAFRules;
use MordenSecurity\Utils\IPUtils;

class Firewall {
    private LoggerSQLite $logger;
    private WAFRules $wafEngine;
    private array $config;

    public function __construct(LoggerSQLite $logger, WAFRules $wafEngine) {
        $this->logger = $logger;
        $this->wafEngine = $wafEngine;
        $this->config = [
            'firewall_enabled' => get_option('ms_firewall_enabled', true),
            'threat_threshold' => get_option('ms_threat_threshold', 7),
        ];
    }

    public function checkRequest(): array {
        if (!$this->config['firewall_enabled']) {
            return ['action' => 'allow', 'reason' => 'firewall_disabled'];
        }

        $requestData = $this->gatherRequestData();
        $violations = $this->wafEngine->evaluateRequest($requestData);

        if (empty($violations)) {
            return ['action' => 'allow', 'reason' => 'no_threats'];
        }

        // Ambil pelanggaran dengan skor tertinggi
        $highestThreat = $violations[0];

        // Jika skor ancaman melebihi ambang batas, blokir permintaan
        if ($highestThreat['threat_score'] >= $this->config['threat_threshold']) {
            return [
                'action' => 'block',
                'reason' => $highestThreat['message'],
                'event_type' => $highestThreat['rule_id'], // Gunakan rule_id sebagai event_type
                'threat_score' => $highestThreat['threat_score'],
                'waf_rule_id' => $highestThreat['rule_db_id'],
                'context' => $highestThreat // Teruskan semua detail pelanggaran
            ];
        }

        return ['action' => 'allow', 'reason' => 'threat_score_below_threshold'];
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

    private function getSecurityHeaders(): array {
        return [
            'accept' => $_SERVER['HTTP_ACCEPT'] ?? '',
            'accept_language' => $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? '',
            'accept_encoding' => $_SERVER['HTTP_ACCEPT_ENCODING'] ?? '',
            'x_forwarded_for' => $_SERVER['HTTP_X_FORWARDED_FOR'] ?? '',
            'x_real_ip' => $_SERVER['HTTP_X_REAL_IP'] ?? ''
        ];
    }
}