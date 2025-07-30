<?php

namespace MordenSecurity\Modules\IPManagement;

use MordenSecurity\Core\LoggerSQLite;
use MordenSecurity\Utils\IPUtils;

if (!defined('ABSPATH')) {
    exit;
}

class CountryBlocker
{
    private LoggerSQLite $logger;
    private array $config;
    private array $countryData;

    public function __construct(LoggerSQLite $logger)
    {
        $this->logger = $logger;
        $this->config = [
            'country_blocking_enabled' => get_option('ms_country_blocking_enabled', false),
            'blocked_countries' => get_option('ms_blocked_countries', []),
            'whitelisted_countries' => get_option('ms_whitelisted_countries', []),
            'block_mode' => get_option('ms_country_block_mode', 'blacklist')
        ];

        $this->loadCountryData();
    }

    public function checkCountryAccess(string $ipAddress): array
    {
        if (!$this->config['country_blocking_enabled']) {
            return ['allowed' => true, 'reason' => 'country_blocking_disabled'];
        }

        $geoData = IPUtils::getIPGeolocation($ipAddress);
        $countryCode = $geoData['country_code'];

        if ($countryCode === 'None' || empty($countryCode)) {
            return ['allowed' => true, 'reason' => 'unknown_country'];
        }

        if ($this->config['block_mode'] === 'whitelist') {
            $allowed = in_array($countryCode, $this->config['whitelisted_countries']);
            $reason = $allowed ? 'country_whitelisted' : 'country_not_whitelisted';
        } else {
            $allowed = !in_array($countryCode, $this->config['blocked_countries']);
            $reason = $allowed ? 'country_allowed' : 'country_blocked';
        }

        if (!$allowed) {
            $this->logCountryBlock($ipAddress, $countryCode);
        }

        return [
            'allowed' => $allowed,
            'reason' => $reason,
            'country_code' => $countryCode,
            'country_name' => $this->getCountryName($countryCode)
        ];
    }

    public function addBlockedCountry(string $countryCode): bool
    {
        $countryCode = strtoupper($countryCode);

        if (!$this->isValidCountryCode($countryCode)) {
            return false;
        }

        $blockedCountries = $this->config['blocked_countries'];

        if (!in_array($countryCode, $blockedCountries)) {
            $blockedCountries[] = $countryCode;
            $this->config['blocked_countries'] = $blockedCountries;

            update_option('ms_blocked_countries', $blockedCountries);

            $this->logger->logSecurityEvent([
                'event_type' => 'country_blocked_added',
                'severity' => 2,
                'ip_address' => IPUtils::getRealClientIP(),
                'message' => "Country {$countryCode} added to block list",
                'context' => ['country_code' => $countryCode],
                'action_taken' => 'country_rule_added'
            ]);

            return true;
        }

        return false;
    }

    public function removeBlockedCountry(string $countryCode): bool
    {
        $countryCode = strtoupper($countryCode);
        $blockedCountries = $this->config['blocked_countries'];

        $key = array_search($countryCode, $blockedCountries);
        if ($key !== false) {
            unset($blockedCountries[$key]);
            $blockedCountries = array_values($blockedCountries);

            $this->config['blocked_countries'] = $blockedCountries;
            update_option('ms_blocked_countries', $blockedCountries);

            return true;
        }

        return false;
    }

    public function getBlockedCountries(): array
    {
        return array_map(function($code) {
            return [
                'code' => $code,
                'name' => $this->getCountryName($code),
                'flag' => $this->getCountryFlag($code)
            ];
        }, $this->config['blocked_countries']);
    }

    public function getCountryStatistics(): array
    {
        $events = $this->logger->getRecentEvents(5000);
        $countryStats = [];
        $blockedByCountry = [];

        foreach ($events as $event) {
            $country = $event['country_code'] ?? 'Unknown';

            if (!isset($countryStats[$country])) {
                $countryStats[$country] = [
                    'code' => $country,
                    'name' => $this->getCountryName($country),
                    'total_requests' => 0,
                    'blocked_requests' => 0,
                    'threat_score' => 0
                ];
            }

            $countryStats[$country]['total_requests']++;

            if (in_array($event['event_type'], ['request_blocked', 'country_blocked'])) {
                $countryStats[$country]['blocked_requests']++;
            }

            $countryStats[$country]['threat_score'] += $event['threat_score'] ?? 0;
        }

        uasort($countryStats, fn($a, $b) => $b['total_requests'] <=> $a['total_requests']);

        return [
            'country_breakdown' => array_slice($countryStats, 0, 20),
            'top_threats' => $this->getTopThreatCountries($countryStats),
            'blocked_countries' => $this->getBlockedCountries()
        ];
    }

    public function getHighRiskCountries(): array
    {
        $riskCountries = [
            'CN' => 'China',
            'RU' => 'Russia',
            'KP' => 'North Korea',
            'IR' => 'Iran',
            'IQ' => 'Iraq',
            'AF' => 'Afghanistan',
            'PK' => 'Pakistan',
            'BD' => 'Bangladesh',
            'VN' => 'Vietnam',
            'UA' => 'Ukraine'
        ];

        return array_map(function($name, $code) {
            return [
                'code' => $code,
                'name' => $name,
                'risk_level' => 'high',
                'is_blocked' => in_array($code, $this->config['blocked_countries'])
            ];
        }, $riskCountries, array_keys($riskCountries));
    }

    private function loadCountryData(): void
    {
        $countryFile = MS_PLUGIN_PATH . 'data/geo-data/country-codes.json';

        if (file_exists($countryFile)) {
            $content = file_get_contents($countryFile);
            $this->countryData = json_decode($content, true) ?: [];
        } else {
            $this->countryData = $this->getDefaultCountryData();
        }
    }

    private function logCountryBlock(string $ipAddress, string $countryCode): void
    {
        $this->logger->logSecurityEvent([
            'event_type' => 'country_blocked',
            'severity' => 2,
            'ip_address' => $ipAddress,
            'message' => "Access blocked from country: {$countryCode}",
            'context' => [
                'country_code' => $countryCode,
                'country_name' => $this->getCountryName($countryCode),
                'block_mode' => $this->config['block_mode']
            ],
            'action_taken' => 'country_blocked',
            'country_code' => $countryCode
        ]);
    }

    private function isValidCountryCode(string $countryCode): bool
    {
        return strlen($countryCode) === 2 &&
               ctype_alpha($countryCode) &&
               isset($this->countryData[$countryCode]);
    }

    private function getCountryName(string $countryCode): string
    {
        return $this->countryData[$countryCode]['name'] ?? 'Unknown';
    }

    private function getCountryFlag(string $countryCode): string
    {
        $flagBase = 0x1F1E6;
        $codePoints = [];

        for ($i = 0; $i < 2; $i++) {
            $codePoints[] = $flagBase + ord($countryCode[$i]) - ord('A');
        }

        return mb_convert_encoding('&#' . implode(';&#', $codePoints) . ';', 'UTF-8', 'HTML-ENTITIES');
    }

    private function getTopThreatCountries(array $countryStats): array
    {
        $threatCountries = array_filter($countryStats, fn($stats) => $stats['threat_score'] > 0);

        uasort($threatCountries, fn($a, $b) => $b['threat_score'] <=> $a['threat_score']);

        return array_slice($threatCountries, 0, 10);
    }

    private function getDefaultCountryData(): array
    {
        return [
            'US' => ['name' => 'United States'],
            'CN' => ['name' => 'China'],
            'RU' => ['name' => 'Russia'],
            'DE' => ['name' => 'Germany'],
            'GB' => ['name' => 'United Kingdom'],
            'FR' => ['name' => 'France'],
            'JP' => ['name' => 'Japan'],
            'BR' => ['name' => 'Brazil'],
            'IN' => ['name' => 'India'],
            'CA' => ['name' => 'Canada']
        ];
    }
}
