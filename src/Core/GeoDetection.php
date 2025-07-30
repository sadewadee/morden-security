<?php

namespace MordenSecurity\Core;

use MordenSecurity\Utils\IPUtils;

if (!defined('ABSPATH')) {
    exit;
}

class GeoDetection
{
    private array $geoDatabase;
    private array $riskCountries;

    public function __construct()
    {
        $this->loadGeoDatabase();
        $this->loadRiskCountries();
    }

    public function getLocationData(string $ipAddress): array
    {
        $geoData = IPUtils::getIPGeolocation($ipAddress);

        return [
            'country_code' => $geoData['country_code'],
            'country_name' => $geoData['country_name'],
            'risk_level' => $this->getRiskLevel($geoData['country_code']),
            'is_high_risk' => $this->isHighRiskCountry($geoData['country_code']),
            'confidence' => $geoData['confidence']
        ];
    }

    public function analyzeGeoRisk(string $ipAddress): array
    {
        $locationData = $this->getLocationData($ipAddress);

        $analysis = [
            'location' => $locationData,
            'risk_factors' => [],
            'risk_score' => 0,
            'recommendation' => 'allow'
        ];

        if ($locationData['is_high_risk']) {
            $analysis['risk_factors'][] = 'high_risk_country';
            $analysis['risk_score'] += 40;
        }

        if ($this->isKnownBotCountry($locationData['country_code'])) {
            $analysis['risk_factors'][] = 'bot_origin_country';
            $analysis['risk_score'] += 25;
        }

        if ($this->hasRecentThreats($locationData['country_code'])) {
            $analysis['risk_factors'][] = 'recent_threat_activity';
            $analysis['risk_score'] += 30;
        }

        $analysis['recommendation'] = $this->getGeoRecommendation($analysis['risk_score']);

        return $analysis;
    }

    private function loadGeoDatabase(): void
    {
        $geoFile = MS_PLUGIN_PATH . 'data/geo-data/country-codes.json';

        if (file_exists($geoFile)) {
            $content = file_get_contents($geoFile);
            $this->geoDatabase = json_decode($content, true) ?: [];
        } else {
            $this->geoDatabase = $this->getDefaultGeoData();
        }
    }

    private function loadRiskCountries(): void
    {
        $riskFile = MS_PLUGIN_PATH . 'data/geo-data/high-risk-countries.json';

        if (file_exists($riskFile)) {
            $content = file_get_contents($riskFile);
            $data = json_decode($content, true) ?: [];
            $this->riskCountries = $data['high_risk_countries'] ?? [];
        } else {
            $this->riskCountries = ['CN', 'RU', 'KP', 'IR', 'IQ'];
        }
    }

    private function getRiskLevel(string $countryCode): string
    {
        if (in_array($countryCode, $this->riskCountries)) {
            return 'high';
        }

        $mediumRisk = ['PK', 'BD', 'VN', 'UA', 'BY'];
        if (in_array($countryCode, $mediumRisk)) {
            return 'medium';
        }

        return 'low';
    }

    private function isHighRiskCountry(string $countryCode): bool
    {
        return in_array($countryCode, $this->riskCountries);
    }

    private function isKnownBotCountry(string $countryCode): bool
    {
        $botCountries = ['CN', 'RU', 'UA', 'VN'];
        return in_array($countryCode, $botCountries);
    }

    private function hasRecentThreats(string $countryCode): bool
    {
        $recentThreats = get_transient('ms_country_threats_' . $countryCode);
        return $recentThreats && $recentThreats > 5;
    }

    private function getGeoRecommendation(int $riskScore): string
    {
        if ($riskScore >= 70) return 'block';
        if ($riskScore >= 40) return 'challenge';
        if ($riskScore >= 20) return 'monitor';
        return 'allow';
    }

    private function getDefaultGeoData(): array
    {
        return [
            'US' => ['name' => 'United States', 'risk' => 'low'],
            'CN' => ['name' => 'China', 'risk' => 'high'],
            'RU' => ['name' => 'Russia', 'risk' => 'high'],
            'DE' => ['name' => 'Germany', 'risk' => 'low'],
            'GB' => ['name' => 'United Kingdom', 'risk' => 'low']
        ];
    }
}
