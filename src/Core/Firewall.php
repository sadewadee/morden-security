<?php

namespace MordenSecurity\Core;

use MordenSecurity\Utils\IPUtils;

if (!defined('ABSPATH')) {
    exit;
}

class Firewall
{
    private LoggerSQLite $logger;
    private array $config;
    private array $requestData;

    public function __construct(LoggerSQLite $logger)
    {
        $this->logger = $logger;
        $this->config = [
            'firewall_enabled' => get_option('ms_firewall_enabled', true),
            'sql_injection_protection' => get_option('ms_sql_injection_protection', true),
            'xss_protection' => get_option('ms_xss_protection', true),
            'lfi_protection' => get_option('ms_lfi_protection', true),
            'rfi_protection' => get_option('ms_rfi_protection', true),
            'command_injection_protection' => get_option('ms_command_injection_protection', true)
        ];

        $this->initializeRequestData();
    }

    public function checkRequest(): array
    {
        if (!$this->config['firewall_enabled']) {
            return ['action' => 'allow', 'reason' => 'firewall_disabled'];
        }

        $threats = [];

        if ($this->config['sql_injection_protection']) {
            $sqlThreat = $this->detectSQLInjection();
            if ($sqlThreat['detected']) {
                $threats[] = $sqlThreat;
            }
        }

        if ($this->config['xss_protection']) {
            $xssThreat = $this->detectXSS();
            if ($xssThreat['detected']) {
                $threats[] = $xssThreat;
            }
        }

        if ($this->config['lfi_protection']) {
            $lfiThreat = $this->detectLFI();
            if ($lfiThreat['detected']) {
                $threats[] = $lfiThreat;
            }
        }

        if ($this->config['rfi_protection']) {
            $rfiThreat = $this->detectRFI();
            if ($rfiThreat['detected']) {
                $threats[] = $rfiThreat;
            }
        }

        if ($this->config['command_injection_protection']) {
            $cmdThreat = $this->detectCommandInjection();
            if ($cmdThreat['detected']) {
                $threats[] = $cmdThreat;
            }
        }

        if (empty($threats)) {
            return ['action' => 'allow', 'reason' => 'no_threats'];
        }

        $highestSeverity = max(array_column($threats, 'severity'));
        $primaryThreat = array_filter($threats, fn($t) => $t['severity'] === $highestSeverity)[0];

        $this->logFirewallEvent($threats);

        return [
            'action' => $highestSeverity >= 8 ? 'block' : 'monitor',
            'reason' => $primaryThreat['type'],
            'threats' => $threats,
            'severity' => $highestSeverity
        ];
    }

    private function detectSQLInjection(): array
    {
        $patterns = [
            '/(\bunion\b.*\bselect\b)/i' => 9,
            '/(\bselect\b.*\bfrom\b.*\bwhere\b)/i' => 8,
            '/(\'.*or.*\'.*=.*\')/i' => 9,
            '/(\bdrop\b.*\btable\b)/i' => 10,
            '/(\binsert\b.*\binto\b)/i' => 7,
            '/(\bupdate\b.*\bset\b)/i' => 7,
            '/(\bdelete\b.*\bfrom\b)/i' => 8,
            '/(benchmark\s*\()/i' => 8,
            '/(sleep\s*\()/i' => 8,
            '/(\bexec\b.*\()/i' => 9
        ];

        foreach ($this->requestData as $source => $data) {
            foreach ($patterns as $pattern => $severity) {
                if (preg_match($pattern, $data)) {
                    return [
                        'detected' => true,
                        'type' => 'sql_injection',
                        'severity' => $severity,
                        'source' => $source,
                        'pattern' => $pattern,
                        'matched_data' => substr($data, 0, 100)
                    ];
                }
            }
        }

        return ['detected' => false];
    }

    private function detectXSS(): array
    {
        $patterns = [
            '/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/i' => 9,
            '/javascript\s*:/i' => 8,
            '/on\w+\s*=\s*["\']?[^"\'>\s]+/i' => 7,
            '/<iframe\b[^>]*>/i' => 8,
            '/<object\b[^>]*>/i' => 7,
            '/<embed\b[^>]*>/i' => 7,
            '/expression\s*\(/i' => 8,
            '/vbscript\s*:/i' => 8
        ];

        foreach ($this->requestData as $source => $data) {
            foreach ($patterns as $pattern => $severity) {
                if (preg_match($pattern, $data)) {
                    return [
                        'detected' => true,
                        'type' => 'xss',
                        'severity' => $severity,
                        'source' => $source,
                        'pattern' => $pattern,
                        'matched_data' => substr($data, 0, 100)
                    ];
                }
            }
        }

        return ['detected' => false];
    }

    private function detectLFI(): array
    {
        $patterns = [
            '/\.\.\/.*\.\.\/.*\.\.\//i' => 9,
            '/\.\.%2f.*\.\.%2f/i' => 9,
            '/(etc\/passwd|etc\/shadow)/i' => 10,
            '/proc\/self\/environ/i' => 9,
            '/\/var\/log\//i' => 7,
            '/boot\.ini/i' => 8,
            '/win\.ini/i' => 8
        ];

        foreach ($this->requestData as $source => $data) {
            foreach ($patterns as $pattern => $severity) {
                if (preg_match($pattern, $data)) {
                    return [
                        'detected' => true,
                        'type' => 'lfi',
                        'severity' => $severity,
                        'source' => $source,
                        'pattern' => $pattern,
                        'matched_data' => substr($data, 0, 100)
                    ];
                }
            }
        }

        return ['detected' => false];
    }

    private function detectRFI(): array
    {
        $patterns = [
            '/https?:\/\/[^\/\s]+/i' => 8,
            '/ftp:\/\/[^\/\s]+/i' => 8,
            '/\?\w+=https?:/i' => 9,
            '/\?\w+=ftp:/i' => 9,
            '/include.*https?:/i' => 9,
            '/require.*https?:/i' => 9
        ];

        foreach ($this->requestData as $source => $data) {
            foreach ($patterns as $pattern => $severity) {
                if (preg_match($pattern, $data) && $source !== 'HTTP_REFERER') {
                    return [
                        'detected' => true,
                        'type' => 'rfi',
                        'severity' => $severity,
                        'source' => $source,
                        'pattern' => $pattern,
                        'matched_data' => substr($data, 0, 100)
                    ];
                }
            }
        }

        return ['detected' => false];
    }

    private function detectCommandInjection(): array
    {
        $patterns = [
            '/;\s*(rm|del|format|shutdown)/i' => 10,
            '/\|\s*(nc|netcat|telnet)/i' => 9,
            '/\$\(.*\)/i' => 8,
            '/`.*`/i' => 8,
            '/&&\s*(cat|ls|ps|id|whoami)/i' => 8,
            '/\|\|\s*(cat|ls|ps|id|whoami)/i' => 8
        ];

        foreach ($this->requestData as $source => $data) {
            foreach ($patterns as $pattern => $severity) {
                if (preg_match($pattern, $data)) {
                    return [
                        'detected' => true,
                        'type' => 'command_injection',
                        'severity' => $severity,
                        'source' => $source,
                        'pattern' => $pattern,
                        'matched_data' => substr($data, 0, 100)
                    ];
                }
            }
        }

        return ['detected' => false];
    }

    private function initializeRequestData(): void
    {
        $this->requestData = [];

        if (!empty($_GET)) {
            $this->requestData['GET'] = implode(' ', array_values($_GET));
        }

        if (!empty($_POST)) {
            $this->requestData['POST'] = implode(' ', array_values($_POST));
        }

        if (!empty($_COOKIE)) {
            $this->requestData['COOKIE'] = implode(' ', array_values($_COOKIE));
        }

        $this->requestData['REQUEST_URI'] = $_SERVER['REQUEST_URI'] ?? '';
        $this->requestData['QUERY_STRING'] = $_SERVER['QUERY_STRING'] ?? '';
        $this->requestData['HTTP_REFERER'] = $_SERVER['HTTP_REFERER'] ?? '';
        $this->requestData['HTTP_USER_AGENT'] = $_SERVER['HTTP_USER_AGENT'] ?? '';
    }

    private function logFirewallEvent(array $threats): void
    {
        $ipAddress = IPUtils::getRealClientIP();
        $primaryThreat = $threats[0];

        $this->logger->logSecurityEvent([
            'event_type' => 'firewall_block',
            'severity' => min($primaryThreat['severity'], 4),
            'ip_address' => $ipAddress,
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
            'request_uri' => $_SERVER['REQUEST_URI'] ?? '',
            'message' => "Firewall detected {$primaryThreat['type']} attack",
            'context' => [
                'threats' => $threats,
                'request_method' => $_SERVER['REQUEST_METHOD'] ?? '',
                'matched_data' => $primaryThreat['matched_data'] ?? ''
            ],
            'action_taken' => $primaryThreat['severity'] >= 8 ? 'blocked' : 'monitored',
            'threat_score' => $primaryThreat['severity'] * 10
        ]);
    }
}
