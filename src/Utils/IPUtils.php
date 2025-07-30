<?php

namespace MordenSecurity\Utils;

if (!defined('ABSPATH')) {
    exit;
}

class IPUtils
{
    private static array $privateRanges = [
        '10.0.0.0/8',
        '172.16.0.0/12',
        '192.168.0.0/16',
        '127.0.0.0/8',
        '169.254.0.0/16',
        '::1/128',
        'fc00::/7',
        'fe80::/10'
    ];

    public static function getRealClientIP(): string
    {
        $headers = [
            'HTTP_CF_CONNECTING_IP',
            'HTTP_CLIENT_IP',
            'HTTP_X_FORWARDED_FOR',
            'HTTP_X_FORWARDED',
            'HTTP_X_CLUSTER_CLIENT_IP',
            'HTTP_FORWARDED_FOR',
            'HTTP_FORWARDED',
            'REMOTE_ADDR'
        ];

        foreach ($headers as $header) {
            if (!empty($_SERVER[$header])) {
                $ip = self::extractFirstValidIP($_SERVER[$header]);
                if ($ip && self::isValidPublicIP($ip)) {
                    return $ip;
                }
            }
        }

        return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    }

    public static function isValidIP(string $ip): bool
    {
        return filter_var($ip, FILTER_VALIDATE_IP) !== false;
    }

    public static function isValidPublicIP(string $ip): bool
    {
        if (!self::isValidIP($ip)) {
            return false;
        }

        return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false;
    }

    public static function isPrivateIP(string $ip): bool
    {
        if (!self::isValidIP($ip)) {
            return false;
        }

        foreach (self::$privateRanges as $range) {
            if (self::ipInRange($ip, $range)) {
                return true;
            }
        }

        return false;
    }

    public static function ipInRange(string $ip, string $range): bool
    {
        if (strpos($range, '/') === false) {
            return $ip === $range;
        }

        list($subnet, $bits) = explode('/', $range);

        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return self::ipv4InRange($ip, $subnet, (int) $bits);
        }

        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            return self::ipv6InRange($ip, $subnet, (int) $bits);
        }

        return false;
    }

    public static function anonymizeIP(string $ip): string
    {
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            $parts = explode('.', $ip);
            $parts[3] = '0';
            return implode('.', $parts);
        }

        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            $parts = explode(':', $ip);
            for ($i = 4; $i < count($parts); $i++) {
                $parts[$i] = '0';
            }
            return implode(':', $parts);
        }

        return $ip;
    }

    public static function getIPGeolocation(string $ip): array
    {
        $geoData = [
            'country_code' => 'None',
            'country_name' => 'None',
            'confidence' => 0
        ];

        $geoHeaders = [
            'HTTP_GEOIP_COUNTRY_CODE',
            'GEOIP_COUNTRY_CODE',
            'HTTP_CF_IPCOUNTRY',
            'MM_COUNTRY_CODE',
            'HTTP_X_COUNTRY_CODE'
        ];

        foreach ($geoHeaders as $header) {
            if (!empty($_SERVER[$header]) && strlen($_SERVER[$header]) === 2) {
                $geoData['country_code'] = strtoupper($_SERVER[$header]);
                $geoData['country_name'] = self::getCountryName($geoData['country_code']);
                $geoData['confidence'] = 85;
                break;
            }
        }

        return $geoData;
    }

    private static function extractFirstValidIP(string $headerValue): ?string
    {
        $ips = array_map('trim', explode(',', $headerValue));

        foreach ($ips as $ip) {
            if (self::isValidIP($ip)) {
                return $ip;
            }
        }

        return null;
    }

    private static function ipv4InRange(string $ip, string $subnet, int $bits): bool
    {
        if ($bits < 0 || $bits > 32) {
            return false;
        }

        $ip = ip2long($ip);
        $subnet = ip2long($subnet);
        $mask = -1 << (32 - $bits);

        return ($ip & $mask) === ($subnet & $mask);
    }

    private static function ipv6InRange(string $ip, string $subnet, int $bits): bool
    {
        if ($bits < 0 || $bits > 128) {
            return false;
        }

        $ip = inet_pton($ip);
        $subnet = inet_pton($subnet);

        $bytesToCheck = intval($bits / 8);
        $bitsToCheck = $bits % 8;

        for ($i = 0; $i < $bytesToCheck; $i++) {
            if ($ip[$i] !== $subnet[$i]) {
                return false;
            }
        }

        if ($bitsToCheck > 0) {
            $mask = 0xFF << (8 - $bitsToCheck);
            if ((ord($ip[$bytesToCheck]) & $mask) !== (ord($subnet[$bytesToCheck]) & $mask)) {
                return false;
            }
        }

        return true;
    }

    private static function getCountryName(string $countryCode): string
    {
        $countries = [
            'US' => 'United States', 'CN' => 'China', 'JP' => 'Japan',
            'DE' => 'Germany', 'GB' => 'United Kingdom', 'FR' => 'France',
            'BR' => 'Brazil', 'IN' => 'India', 'RU' => 'Russia',
            'CA' => 'Canada', 'AU' => 'Australia', 'KR' => 'South Korea'
        ];

        return $countries[$countryCode] ?? 'Unknown';
    }
    public static function getIPDetails(string $ipAddress): array {
    // Validasi IP
    if (!self::isValidIP($ipAddress)) {
        return [
            'success' => false,
            'error' => 'Invalid IP address format'
        ];
    }

    // Check cache first
    $cacheKey = 'ms_ip_details_' . md5($ipAddress);
    $cached = get_transient($cacheKey);
    if ($cached !== false) {
        return $cached;
    }

    // Skip private IPs
    if (self::isPrivateIP($ipAddress)) {
        return [
            'success' => true,
            'ip' => $ipAddress,
            'country_code' => 'LOCAL',
            'country_name' => 'Local Network',
            'city' => 'Private',
            'is_private' => true
        ];
    }

    // Try free IP API services
    $apis = [
        'http://ip-api.com/json/' . $ipAddress . '?fields=status,country,countryCode,region,regionName,city,isp,org,timezone,query',
        'https://ipapi.co/' . $ipAddress . '/json/',
    ];

    foreach ($apis as $url) {
        $result = self::makeAPIRequest($url);
        if ($result['success']) {
            // Cache for 24 hours
            set_transient($cacheKey, $result, 24 * HOUR_IN_SECONDS);
            return $result;
        }
    }

    // Fallback to local geo detection
    $geoData = self::getGeoLocation($ipAddress);
    return [
        'success' => true,
        'ip' => $ipAddress,
        'country_code' => $geoData['country_code'],
        'country_name' => $geoData['country_name'],
        'city' => 'Unknown',
        'source' => 'local_headers'
    ];
}

private static function makeAPIRequest(string $url): array {
    $args = [
        'timeout' => 10,
        'headers' => [
            'User-Agent' => 'Mozilla/5.0 (compatible; MordenSecurity/1.0)',
            'Accept' => 'application/json'
        ],
        'sslverify' => false // untuk menghindari SSL issues
    ];

    $response = wp_remote_get($url, $args);

    if (is_wp_error($response)) {
        return [
            'success' => false,
            'error' => $response->get_error_message()
        ];
    }

    $statusCode = wp_remote_retrieve_response_code($response);
    if ($statusCode !== 200) {
        return [
            'success' => false,
            'error' => "HTTP Error: {$statusCode}"
        ];
    }

    $body = wp_remote_retrieve_body($response);
    $data = json_decode($body, true);

    if (json_last_error() !== JSON_ERROR_NONE) {
        return [
            'success' => false,
            'error' => 'Invalid JSON response'
        ];
    }

    // Normalize data berdasarkan provider
    if (isset($data['status']) && $data['status'] === 'fail') {
        return [
            'success' => false,
            'error' => $data['message'] ?? 'API request failed'
        ];
    }

    return [
        'success' => true,
        'ip' => $data['query'] ?? $data['ip'] ?? '',
        'country_code' => $data['countryCode'] ?? $data['country_code'] ?? 'UNKNOWN',
        'country_name' => $data['country'] ?? $data['country_name'] ?? 'Unknown',
        'city' => $data['city'] ?? 'Unknown',
        'region' => $data['regionName'] ?? $data['region'] ?? '',
        'isp' => $data['isp'] ?? $data['org'] ?? '',
        'timezone' => $data['timezone'] ?? ''
    ];
}
}
