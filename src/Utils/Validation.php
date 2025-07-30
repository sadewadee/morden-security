<?php

namespace MordenSecurity\Utils;

if (!defined('ABSPATH')) {
    exit;
}

class Validation
{
    public static function sanitizeIPAddress(string $ip): string
    {
        $ip = trim($ip);

        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return $ip;
        }

        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            return $ip;
        }

        return '';
    }

    public static function validateCIDRRange(string $cidr): bool
    {
        if (strpos($cidr, '/') === false) {
            return self::isValidIP($cidr);
        }

        list($ip, $prefix) = explode('/', $cidr, 2);

        if (!self::isValidIP($ip)) {
            return false;
        }

        $prefixLength = (int) $prefix;

        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return $prefixLength >= 0 && $prefixLength <= 32;
        }

        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            return $prefixLength >= 0 && $prefixLength <= 128;
        }

        return false;
    }

    public static function sanitizeUserAgent(string $userAgent): string
    {
        $userAgent = trim($userAgent);
        $userAgent = substr($userAgent, 0, 512);
        return wp_strip_all_tags($userAgent);
    }

    public static function sanitizeURL(string $url): string
    {
        $url = trim($url);
        $url = filter_var($url, FILTER_SANITIZE_URL);

        if (!filter_var($url, FILTER_VALIDATE_URL)) {
            return '';
        }

        return $url;
    }

    public static function validateThreatScore(int $score): int
    {
        return max(0, min(1000, $score));
    }

    public static function validateSeverityLevel(int $severity): int
    {
        return max(1, min(4, $severity));
    }

    public static function sanitizeEventType(string $eventType): string
    {
        $allowedTypes = [
            'request_blocked', 'request_allowed', 'request_challenged',
            'bot_detected', 'bot_suspicious', 'bot_malicious',
            'firewall_block', 'firewall_monitor',
            'login_failed', 'login_success',
            'xmlrpc_request', 'ip_auto_blocked'
        ];

        $eventType = sanitize_key($eventType);

        return in_array($eventType, $allowedTypes) ? $eventType : 'unknown';
    }

    public static function validateBlockDuration(string $duration): string
    {
        $allowedDurations = ['temporary', 'permanent'];
        return in_array($duration, $allowedDurations) ? $duration : 'temporary';
    }

    public static function validateRuleType(string $ruleType): string
    {
        $allowedTypes = ['whitelist', 'blacklist', 'auto_blocked'];
        return in_array($ruleType, $allowedTypes) ? $ruleType : 'blacklist';
    }

    public static function sanitizeCountryCode(string $countryCode): string
    {
        $countryCode = strtoupper(trim($countryCode));

        if (strlen($countryCode) === 2 && ctype_alpha($countryCode)) {
            return $countryCode;
        }

        return 'XX';
    }

    public static function isValidJSON(string $json): bool
    {
        json_decode($json);
        return json_last_error() === JSON_ERROR_NONE;
    }

    public static function sanitizeLogMessage(string $message): string
    {
        $message = trim($message);
        $message = substr($message, 0, 1000);
        return wp_strip_all_tags($message);
    }

    public static function validateTimeWindow(int $timeWindow): int
    {
        $minWindow = 60;
        $maxWindow = 86400 * 30;

        return max($minWindow, min($maxWindow, $timeWindow));
    }

    public static function sanitizeRequestData(array $data): array
    {
        $sanitized = [];

        foreach ($data as $key => $value) {
            $key = sanitize_key($key);

            if (is_array($value)) {
                $sanitized[$key] = self::sanitizeRequestData($value);
            } else {
                $sanitized[$key] = sanitize_text_field($value);
            }
        }

        return $sanitized;
    }

    private static function isValidIP(string $ip): bool
    {
        return filter_var($ip, FILTER_VALIDATE_IP) !== false;
    }
}
