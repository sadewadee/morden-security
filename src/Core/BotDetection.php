<?php

namespace MordenSecurity\Core;

use MordenSecurity\Utils\IPUtils;

if (!defined('ABSPATH')) {
    exit;
}

class BotDetection
{
    private LoggerSQLite $logger;
    private array $botSignatures = [];
    private array $customWhitelist = [];
    private array $config;

    public function __construct(LoggerSQLite $logger)
    {
        $this->logger = $logger;
        $this->loadBotSignatures();
        $this->loadCustomWhitelist();
        $this->config = [
            'bot_detection_enabled' => get_option('ms_bot_detection_enabled', true),
            'aggressive_detection' => get_option('ms_aggressive_bot_detection', false),
            'challenge_threshold' => get_option('ms_bot_challenge_threshold', 70),
            'block_threshold' => get_option('ms_bot_block_threshold', 100) // Increased threshold for cumulative score
        ];
    }

    public function analyzeRequest(): array
    {
        if (!$this->config['bot_detection_enabled']) {
            return ['is_bot' => false, 'confidence' => 0, 'type' => 'detection_disabled', 'action' => 'allow'];
        }

        $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
        $ipAddress = IPUtils::getRealClientIP();

        // First, check against the custom whitelist from the database
        if ($this->isCustomWhitelisted($userAgent)) {
            return ['is_bot' => true, 'confidence' => 0, 'type' => 'custom_whitelist', 'action' => 'allow'];
        }

        $analysis = [
            'is_bot' => false,
            'confidence' => 0,
            'type' => 'human',
            'details' => [],
            'action' => 'allow'
        ];

        // Cumulative scoring
        $totalConfidence = 0;
        $details = [];

        // 1. Signature Matching
        $signatureMatch = $this->checkUserAgentSignatures($userAgent);
        if ($signatureMatch['confidence'] > 0) {
            $totalConfidence += $signatureMatch['confidence'];
            $details['signature_match'] = $signatureMatch;
        }

        // If it's a known good bot, stop here and allow.
        if ($signatureMatch['type'] === 'good_bot') {
            $this->logBotDetection($signatureMatch, $ipAddress, $userAgent, 'allow');
            return ['is_bot' => true, 'confidence' => 0, 'type' => 'good_bot', 'action' => 'allow'];
        }

        // 2. Behavior Analysis
        $behaviorScore = $this->analyzeBehaviorPatterns($ipAddress);
        if ($behaviorScore > 0) {
            $totalConfidence += $behaviorScore;
            $details['behavior_score'] = $behaviorScore;
        }

        // 3. Header Analysis
        $headerAnalysis = $this->analyzeHeaders();
        if ($headerAnalysis['confidence'] > 0) {
            $totalConfidence += $headerAnalysis['confidence'];
            $details['header_analysis'] = $headerAnalysis;
        }

        // 4. Timing Analysis
        $timingAnalysis = $this->analyzeRequestTiming($ipAddress);
        if ($timingAnalysis['confidence'] > 0) {
            $totalConfidence += $timingAnalysis['confidence'];
            $details['timing_analysis'] = $timingAnalysis;
        }

        $analysis['confidence'] = min($totalConfidence, 150); // Cap confidence to prevent extreme scores
        $analysis['details'] = $details;

        if ($analysis['confidence'] >= $this->config['block_threshold']) {
            $analysis['is_bot'] = true;
            $analysis['type'] = $signatureMatch['type'] !== 'unknown' ? $signatureMatch['type'] : 'behavioral_block';
            $analysis['action'] = 'block';
        } elseif ($analysis['confidence'] >= $this->config['challenge_threshold']) {
            $analysis['is_bot'] = true;
            $analysis['type'] = $signatureMatch['type'] !== 'unknown' ? $signatureMatch['type'] : 'behavioral_challenge';
            $analysis['action'] = 'challenge';
        }

        if ($analysis['is_bot']) {
            $this->logBotDetection($analysis, $ipAddress, $userAgent, $analysis['action']);
        }

        return $analysis;
    }

    private function loadBotSignatures(): void
    {
        $signatureFiles = glob(MS_PLUGIN_PATH . 'data/bot-signatures/*.json');
        $this->botSignatures = [];

        foreach ($signatureFiles as $file) {
            $type = basename($file, '.json'); // e.g., 'malicious-bots'
            $category = str_replace(['-bots', '-crawlers'], '', $type); // Simplifies to 'malicious', 'search-engines', etc.

            $content = file_get_contents($file);
            $signatures = json_decode($content, true);

            if (is_array($signatures)) {
                foreach ($signatures as $signature) {
                    if (!empty($signature['pattern'])) {
                        $this->botSignatures[] = [
                            'pattern' => '/' . preg_quote($signature['pattern'], '/') . '/i',
                            'type' => $signature['type'] ?? $category,
                            'confidence' => $signature['confidence'] ?? ($category === 'malicious' ? 110 : 0) // High confidence for malicious, 0 for good
                        ];
                    }
                }
            }
        }
    }

    private function loadCustomWhitelist(): void
    {
        $this->customWhitelist = $this->logger->getBotWhitelistRules();
    }

    private function isCustomWhitelisted(string $userAgent): bool
    {
        foreach ($this->customWhitelist as $rule) {
            if (!empty($rule['user_agent_pattern'])) {
                $pattern = '/' . preg_quote($rule['user_agent_pattern'], '/') . '/i';
                if (preg_match($pattern, $userAgent)) {
                    return true;
                }
            }
        }
        return false;
    }

    private function checkUserAgentSignatures(string $userAgent): array
    {
        if (empty($userAgent)) {
            return ['confidence' => 85, 'type' => 'no_user_agent', 'matched' => 'empty_ua'];
        }

        foreach ($this->botSignatures as $signature) {
            if (preg_match($signature['pattern'], $userAgent)) {
                // If it's a good bot, confidence is 0, but we identify it.
                if (in_array($signature['type'], ['search-engine', 'social', 'monitoring'])) {
                     return ['confidence' => 0, 'type' => 'good_bot', 'matched' => $signature['pattern']];
                }
                return ['confidence' => $signature['confidence'], 'type' => $signature['type'], 'matched' => $signature['pattern']];
            }
        }

        // Check for generic suspicious patterns if no specific signature matched
        $suspiciousPatterns = [
            '/bot/i' => 40,
            '/spider/i' => 40,
            '/crawler/i' => 50,
            '/scraper/i' => 60,
            '/scanner/i' => 80,
        ];

        foreach ($suspiciousPatterns as $pattern => $confidence) {
            if (preg_match($pattern, $userAgent)) {
                return ['confidence' => $confidence, 'type' => 'suspicious_pattern', 'matched' => $pattern];
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

        if ($recentRequests > 60) {
            $behaviorScore += 50; // High request rate
        } elseif ($recentRequests > 25) {
            $behaviorScore += 25;
        }

        if ($pageVariety < 2 && $recentRequests > 10) {
            $behaviorScore += 30; // Low page variety with multiple requests
        }

        if ($sessionLength < 5 && $recentRequests > 5) {
            $behaviorScore += 15; // Very short session
        }

        return min($behaviorScore, 100);
    }

    private function analyzeHeaders(): array
    {
        $suspiciousHeaders = 0;
        $details = [];

        if (empty($_SERVER['HTTP_ACCEPT'])) {
            $suspiciousHeaders += 20;
            $details[] = 'missing_accept_header';
        }

        if (empty($_SERVER['HTTP_ACCEPT_LANGUAGE'])) {
            $suspiciousHeaders += 15;
            $details[] = 'missing_language_header';
        }

        if (strpos($_SERVER['HTTP_USER_AGENT'] ?? '', 'python-requests') !== false) {
             $suspiciousHeaders += 40;
             $details[] = 'python_requests_ua';
        }

        if (!empty($_SERVER['HTTP_X_FORWARDED_FOR']) && count(explode(',', $_SERVER['HTTP_X_FORWARDED_FOR'])) > 3) {
            $suspiciousHeaders += 25;
            $details[] = 'excessive_proxy_chain';
        }

        return ['confidence' => min($suspiciousHeaders, 100), 'details' => $details];
    }

    private function analyzeRequestTiming(string $ipAddress): array
    {
        $recentRequests = $this->getRecentRequestTimings($ipAddress, 60);

        if (count($recentRequests) < 3) {
            return ['confidence' => 0, 'pattern' => 'insufficient_data'];
        }

        $intervals = [];
        for ($i = 1; $i < count($recentRequests); $i++) {
            $intervals[] = $recentRequests[$i] - $recentRequests[$i - 1];
        }

        $avgInterval = array_sum($intervals) / count($intervals);
        $variance = $this->calculateVariance($intervals, $avgInterval);

        if ($avgInterval < 1.5 && $variance < 0.5) {
            return ['confidence' => 80, 'pattern' => 'machine_like_timing'];
        }

        if ($avgInterval < 4 && $variance < 1.0) {
            return ['confidence' => 50, 'pattern' => 'suspicious_timing'];
        }

        return ['confidence' => 0, 'pattern' => 'human_like_timing'];
    }

    private function logBotDetection(array $analysis, string $ipAddress, string $userAgent, string $action): void
    {
        $this->logger->logSecurityEvent([
            'event_type' => 'bot_detected',
            'severity' => $analysis['confidence'] > 90 ? 3 : 2,
            'ip_address' => $ipAddress,
            'user_agent' => $userAgent,
            'message' => sprintf(
                "Bot detection: %s (Confidence: %d%%) - Action: %s",
                $analysis['type'],
                $analysis['confidence'],
                $action
            ),
            'context' => $analysis['details'],
            'action_taken' => $action,
            'threat_score' => $analysis['confidence']
        ]);
    }

    // --- Helper and mock functions ---

    private function getRecentRequestCount(string $ipAddress, int $timeWindow): int
    {
        // Mock implementation - replace with real database query
        return rand(1, 70);
    }

    private function getPageVarietyScore(string $ipAddress, int $timeWindow): int
    {
        // Mock implementation
        return rand(1, 5);
    }

    private function getSessionLength(string $ipAddress): int
    {
        // Mock implementation
        return rand(3, 60);
    }

    private function getRecentRequestTimings(string $ipAddress, int $timeWindow): array
    {
        // Mock implementation
        return [time() - 10, time() - 8, time() - 5, time() - 2];
    }

    private function calculateVariance(array $values, float $mean): float
    {
        if (count($values) === 0) return 0;
        $variance = 0;
        foreach ($values as $value) {
            $variance += pow($value - $mean, 2);
        }
        return $variance / count($values);
    }
}