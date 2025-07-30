<?php

namespace MordenSecurity\Core;

use MordenSecurity\Utils\IPUtils;

if (!defined('ABSPATH')) {
    exit;
}

class BotDetection
{
    private LoggerSQLite $logger;
    private array $botSignatures;
    private array $behaviorPatterns;
    private array $config;

    public function __construct(LoggerSQLite $logger)
    {
        $this->logger = $logger;
        $this->loadBotSignatures();
        $this->initializeBehaviorPatterns();
        $this->config = [
            'bot_detection_enabled' => get_option('ms_bot_detection_enabled', true),
            'aggressive_detection' => get_option('ms_aggressive_bot_detection', false),
            'challenge_threshold' => get_option('ms_bot_challenge_threshold', 70),
            'block_threshold' => get_option('ms_bot_block_threshold', 90)
        ];
    }

    public function analyzeRequest(): array
    {
        if (!$this->config['bot_detection_enabled']) {
            return ['is_bot' => false, 'confidence' => 0, 'type' => 'detection_disabled'];
        }

        $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
        $ipAddress = IPUtils::getRealClientIP();

        $analysis = [
            'is_bot' => false,
            'confidence' => 0,
            'type' => 'human',
            'details' => [],
            'action' => 'allow'
        ];

        $signatureMatch = $this->checkUserAgentSignatures($userAgent);
        $behaviorScore = $this->analyzeBehaviorPatterns($ipAddress);
        $headerAnalysis = $this->analyzeHeaders();
        $timingAnalysis = $this->analyzeRequestTiming($ipAddress);

        $totalConfidence = max(
            $signatureMatch['confidence'],
            $behaviorScore,
            $headerAnalysis['confidence'],
            $timingAnalysis['confidence']
        );

        $analysis['confidence'] = $totalConfidence;
        $analysis['details'] = [
            'signature_match' => $signatureMatch,
            'behavior_score' => $behaviorScore,
            'header_analysis' => $headerAnalysis,
            'timing_analysis' => $timingAnalysis
        ];

        if ($totalConfidence >= $this->config['block_threshold']) {
            $analysis['is_bot'] = true;
            $analysis['type'] = $signatureMatch['type'] ?? 'malicious_bot';
            $analysis['action'] = 'block';
        } elseif ($totalConfidence >= $this->config['challenge_threshold']) {
            $analysis['is_bot'] = true;
            $analysis['type'] = 'suspicious_bot';
            $analysis['action'] = 'challenge';
        }

        $this->logBotDetection($analysis, $ipAddress, $userAgent);

        return $analysis;
    }

    public function isMaliciousBot(string $userAgent, string $ipAddress): bool
    {
        $maliciousPatterns = [
            '/sqlmap/i',
            '/nikto/i',
            '/nmap/i',
            '/masscan/i',
            '/zgrab/i',
            '/python-requests/i',
            '/curl\/[\d\.]+$/i',
            '/wget/i',
            '/libwww-perl/i'
        ];

        foreach ($maliciousPatterns as $pattern) {
            if (preg_match($pattern, $userAgent)) {
                return true;
            }
        }

        if ($this->hasHighThreatBehavior($ipAddress)) {
            return true;
        }

        return false;
    }

    public function isGoodBot(string $userAgent): bool
    {
        $goodBotPatterns = [
            '/googlebot/i',
            '/bingbot/i',
            '/slurp/i',
            '/duckduckbot/i',
            '/baiduspider/i',
            '/yandexbot/i',
            '/facebookexternalhit/i',
            '/twitterbot/i',
            '/linkedinbot/i',
            '/applebot/i'
        ];

        foreach ($goodBotPatterns as $pattern) {
            if (preg_match($pattern, $userAgent)) {
                return true;
            }
        }

        return false;
    }

    private function loadBotSignatures(): void
    {
        $signaturesFile = MS_PLUGIN_PATH . 'data/bot-signatures/malicious-bots.json';

        if (file_exists($signaturesFile)) {
            $content = file_get_contents($signaturesFile);
            $this->botSignatures = json_decode($content, true) ?: [];
        } else {
            $this->botSignatures = $this->getDefaultBotSignatures();
        }
    }

    private function checkUserAgentSignatures(string $userAgent): array
    {
        if (empty($userAgent)) {
            return ['confidence' => 85, 'type' => 'no_user_agent', 'matched' => 'empty_ua'];
        }

        if ($this->isGoodBot($userAgent)) {
            return ['confidence' => 0, 'type' => 'good_bot', 'matched' => 'whitelist'];
        }

        if ($this->isMaliciousBot($userAgent, '')) {
            return ['confidence' => 95, 'type' => 'malicious_bot', 'matched' => 'signature'];
        }

        $suspiciousPatterns = [
            '/bot/i' => 60,
            '/spider/i' => 60,
            '/crawler/i' => 60,
            '/scraper/i' => 80,
            '/scanner/i' => 90,
            '/wordpress/i' => 70
        ];

        foreach ($suspiciousPatterns as $pattern => $confidence) {
            if (preg_match($pattern, $userAgent)) {
                return ['confidence' => $confidence, 'type' => 'suspicious_bot', 'matched' => $pattern];
            }
        }

        return ['confidence' => 0, 'type' => 'unknown', 'matched' => 'none'];
    }

    private function analyzeBehaviorPatterns(string $ipAddress): int
    {
        $recentRequests = $this->getRecentRequestCount($ipAddress, 300);
        $pageVariety = $this->getPageVarietyScore($ipAddress, 3600);
        $sessionLength = $this->getSessionLength($ipAddress);

        $behaviorScore = 0;

        if ($recentRequests > 50) {
            $behaviorScore += 60;
        } elseif ($recentRequests > 20) {
            $behaviorScore += 30;
        }

        if ($pageVariety < 2) {
            $behaviorScore += 40;
        }

        if ($sessionLength < 5) {
            $behaviorScore += 20;
        }

        return min($behaviorScore, 100);
    }

    private function analyzeHeaders(): array
    {
        $suspiciousHeaders = 0;
        $details = [];

        if (empty($_SERVER['HTTP_ACCEPT'])) {
            $suspiciousHeaders += 20;
            $details[] = 'missing_accept';
        }

        if (empty($_SERVER['HTTP_ACCEPT_LANGUAGE'])) {
            $suspiciousHeaders += 15;
            $details[] = 'missing_language';
        }

        if (empty($_SERVER['HTTP_ACCEPT_ENCODING'])) {
            $suspiciousHeaders += 15;
            $details[] = 'missing_encoding';
        }

        if (!empty($_SERVER['HTTP_X_FORWARDED_FOR']) &&
            count(explode(',', $_SERVER['HTTP_X_FORWARDED_FOR'])) > 3) {
            $suspiciousHeaders += 25;
            $details[] = 'proxy_chain';
        }

        return [
            'confidence' => min($suspiciousHeaders, 100),
            'details' => $details
        ];
    }

    private function analyzeRequestTiming(string $ipAddress): array
    {
        $recentRequests = $this->getRecentRequestTimings($ipAddress, 60);

        if (count($recentRequests) < 2) {
            return ['confidence' => 0, 'pattern' => 'insufficient_data'];
        }

        $intervals = [];
        for ($i = 1; $i < count($recentRequests); $i++) {
            $intervals[] = $recentRequests[$i] - $recentRequests[$i-1];
        }

        $avgInterval = array_sum($intervals) / count($intervals);
        $variance = $this->calculateVariance($intervals, $avgInterval);

        if ($avgInterval < 2 && $variance < 0.5) {
            return ['confidence' => 90, 'pattern' => 'machine_timing'];
        }

        if ($avgInterval < 5 && $variance < 1.0) {
            return ['confidence' => 60, 'pattern' => 'suspicious_timing'];
        }

        return ['confidence' => 0, 'pattern' => 'human_timing'];
    }

    private function hasHighThreatBehavior(string $ipAddress): bool
    {
        $threatScore = $this->logger->getIPThreatScore($ipAddress, 3600);
        return $threatScore > 100;
    }

    private function getRecentRequestCount(string $ipAddress, int $timeWindow): int
    {
        $events = $this->logger->getRecentEvents(1000, [
            'ip_address' => $ipAddress,
            'timestamp_after' => time() - $timeWindow
        ]);

        return count($events);
    }

    private function getPageVarietyScore(string $ipAddress, int $timeWindow): int
    {
        return 3;
    }

    private function getSessionLength(string $ipAddress): int
    {
        return 30;
    }

    private function getRecentRequestTimings(string $ipAddress, int $timeWindow): array
    {
        return [time() - 30, time() - 20, time() - 10];
    }

    private function calculateVariance(array $values, float $mean): float
    {
        $variance = 0;
        foreach ($values as $value) {
            $variance += pow($value - $mean, 2);
        }
        return $variance / count($values);
    }

    private function logBotDetection(array $analysis, string $ipAddress, string $userAgent): void
    {
        if ($analysis['confidence'] > 50) {
            $this->logger->logSecurityEvent([
                'event_type' => $analysis['is_bot'] ? 'bot_detected' : 'bot_suspicious',
                'severity' => $analysis['confidence'] > 80 ? 3 : 2,
                'ip_address' => $ipAddress,
                'user_agent' => $userAgent,
                'message' => "Bot detection: {$analysis['type']} (confidence: {$analysis['confidence']}%)",
                'context' => $analysis['details'],
                'action_taken' => $analysis['action'],
                'threat_score' => $analysis['confidence']
            ]);
        }
    }

    private function initializeBehaviorPatterns(): void
    {
        $this->behaviorPatterns = [
            'rapid_requests' => ['threshold' => 20, 'window' => 300, 'score' => 60],
            'no_session' => ['threshold' => 5, 'score' => 40],
            'linear_browsing' => ['threshold' => 2, 'score' => 30]
        ];
    }

    private function getDefaultBotSignatures(): array
    {
        return [
            'malicious' => [
                'sqlmap', 'nikto', 'nmap', 'masscan', 'zgrab'
            ],
            'good' => [
                'googlebot', 'bingbot', 'slurp', 'duckduckbot'
            ]
        ];
    }
}
