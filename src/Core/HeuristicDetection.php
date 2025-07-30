<?php

namespace MordenSecurity\Core;

use MordenSecurity\Utils\IPUtils;

if (!defined('ABSPATH')) {
    exit;
}

class HeuristicDetection
{
    private LoggerSQLite $logger;
    private array $patterns;

    public function __construct(LoggerSQLite $logger)
    {
        $this->logger = $logger;
        $this->loadHeuristicPatterns();
    }

    public function analyzeRequest(): array
    {
        $analysis = [
            'threat_indicators' => [],
            'risk_score' => 0,
            'confidence' => 0,
            'recommendation' => 'allow'
        ];

        $requestData = $this->gatherRequestData();

        foreach ($this->patterns as $patternGroup => $patterns) {
            $result = $this->checkPatterns($patterns, $requestData);
            if ($result['matches']) {
                $analysis['threat_indicators'][] = [
                    'type' => $patternGroup,
                    'matches' => $result['matches'],
                    'severity' => $result['severity']
                ];
                $analysis['risk_score'] += $result['severity'];
            }
        }

        $analysis['confidence'] = $this->calculateConfidence($analysis['risk_score']);
        $analysis['recommendation'] = $this->getRecommendation($analysis['risk_score']);

        return $analysis;
    }

    private function loadHeuristicPatterns(): void
    {
        $this->patterns = [
            'file_access' => [
                ['pattern' => '/\.(php|asp|jsp|cgi)$/i', 'severity' => 30],
                ['pattern' => '/wp-config\.php/i', 'severity' => 50],
                ['pattern' => '/\.htaccess/i', 'severity' => 40]
            ],
            'malicious_requests' => [
                ['pattern' => '/union.*select/i', 'severity' => 60],
                ['pattern' => '/<script.*>/i', 'severity' => 50],
                ['pattern' => '/eval\(/i', 'severity' => 70]
            ],
            'scanning_behavior' => [
                ['pattern' => '/admin.*login/i', 'severity' => 20],
                ['pattern' => '/wp-admin.*ajax/i', 'severity' => 15],
                ['pattern' => '/xmlrpc\.php/i', 'severity' => 25]
            ]
        ];
    }

    private function gatherRequestData(): array
    {
        return [
            'uri' => $_SERVER['REQUEST_URI'] ?? '',
            'query' => $_SERVER['QUERY_STRING'] ?? '',
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
            'referer' => $_SERVER['HTTP_REFERER'] ?? '',
            'method' => $_SERVER['REQUEST_METHOD'] ?? 'GET',
            'post_data' => http_build_query($_POST ?? [])
        ];
    }

    private function checkPatterns(array $patterns, array $requestData): array
    {
        $matches = [];
        $totalSeverity = 0;

        foreach ($patterns as $patternConfig) {
            $pattern = $patternConfig['pattern'];
            $severity = $patternConfig['severity'];

            foreach ($requestData as $field => $data) {
                if (preg_match($pattern, $data)) {
                    $matches[] = [
                        'field' => $field,
                        'pattern' => $pattern,
                        'matched_data' => substr($data, 0, 100)
                    ];
                    $totalSeverity += $severity;
                }
            }
        }

        return [
            'matches' => $matches,
            'severity' => $totalSeverity
        ];
    }

    private function calculateConfidence(int $riskScore): int
    {
        if ($riskScore >= 100) return 95;
        if ($riskScore >= 50) return 80;
        if ($riskScore >= 25) return 60;
        if ($riskScore >= 10) return 40;
        return 20;
    }

    private function getRecommendation(int $riskScore): string
    {
        if ($riskScore >= 80) return 'block';
        if ($riskScore >= 50) return 'challenge';
        if ($riskScore >= 25) return 'monitor';
        return 'allow';
    }
}
