<?php

namespace MordenSecurity\Modules\AntiSpam;

use MordenSecurity\Core\LoggerSQLite;
use MordenSecurity\Utils\IPUtils;

if (!defined('ABSPATH')) {
    exit;
}

class BehaviorTracker
{
    private LoggerSQLite $logger;
    private string $cachePrefix = 'ms_behavior_';

    public function __construct(LoggerSQLite $logger)
    {
        $this->logger = $logger;
    }

    public function trackVisitor(string $ipAddress): array
    {
        $sessionKey = $this->cachePrefix . md5($ipAddress);
        $behavior = get_transient($sessionKey) ?: $this->initializeBehavior();

        $behavior['page_views']++;
        $behavior['last_activity'] = time();
        $behavior['session_duration'] = time() - $behavior['session_start'];
        $behavior['pages_visited'][] = $_SERVER['REQUEST_URI'] ?? '';
        $behavior['pages_visited'] = array_slice($behavior['pages_visited'], -20);

        set_transient($sessionKey, $behavior, 3600);

        return $this->analyzeBehavior($behavior);
    }

    public function getBehaviorScore(string $ipAddress): int
    {
        $behavior = $this->trackVisitor($ipAddress);
        $score = 0;

        if ($behavior['page_views'] > 50) $score += 30;
        if ($behavior['session_duration'] < 5) $score += 20;
        if (count(array_unique($behavior['pages_visited'])) < 3) $score += 25;
        if ($behavior['suspicious_patterns']) $score += 40;

        return min($score, 100);
    }

    private function initializeBehavior(): array
    {
        return [
            'session_start' => time(),
            'page_views' => 0,
            'last_activity' => time(),
            'session_duration' => 0,
            'pages_visited' => [],
            'suspicious_patterns' => false
        ];
    }

    private function analyzeBehavior(array $behavior): array
    {
        $suspiciousPatterns = [
            '/wp-admin/', '/wp-config/', '/.env', '/xmlrpc.php'
        ];

        foreach ($behavior['pages_visited'] as $page) {
            foreach ($suspiciousPatterns as $pattern) {
                if (strpos($page, $pattern) !== false) {
                    $behavior['suspicious_patterns'] = true;
                    break 2;
                }
            }
        }

        return $behavior;
    }
}
