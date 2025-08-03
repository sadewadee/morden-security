<?php

namespace MordenSecurity\Admin;

use MordenSecurity\Core\LoggerSQLite;
use MordenSecurity\Modules\IPManagement\CountryBlocker;

if (!defined('ABSPATH')) {
    exit;
}

class CountryManagementPage
{
    private LoggerSQLite $logger;
    private CountryBlocker $countryBlocker;

    public function __construct(LoggerSQLite $logger)
    {
        $this->logger = $logger;
        $this->countryBlocker = new CountryBlocker($logger);
    }

    public function render(): void
    {
        $activeTab = sanitize_key($_GET['tab'] ?? 'overview');
        $statistics = $this->countryBlocker->getCountryStatistics();
        $blockedCountries = $this->countryBlocker->getBlockedCountries();
        $topThreatCountries = $statistics['top_threats'];

        ?>
        <div class="wrap ms-country-management-page">
            <h1><?php _e('Country Management', 'morden-security'); ?></h1>

            <nav class="nav-tab-wrapper">
                <a href="?page=morden-security-countries&tab=overview"
                   class="nav-tab <?php echo $activeTab === 'overview' ? 'nav-tab-active' : ''; ?>">
                    <?php _e('Overview', 'morden-security'); ?>
                </a>
                <a href="?page=morden-security-countries&tab=blocked"
                   class="nav-tab <?php echo $activeTab === 'blocked' ? 'nav-tab-active' : ''; ?>">
                    <?php _e('Blocked Countries', 'morden-security'); ?>
                </a>
            </nav>

            <div class="tab-content">
                <?php
                switch ($activeTab) {
                    case 'overview':
                        $this->renderOverviewTab($statistics);
                        break;
                    case 'blocked':
                        $this->renderBlockedCountriesTab($blockedCountries, $topThreatCountries);
                        break;
                }
                ?>
            </div>
        </div>
        <?php
    }

    private function renderOverviewTab(array $statistics): void
    {
        ?>
        <div class="ms-dashboard-columns">
            <div class="ms-dashboard-main">
                <div class="ms-stats-grid">
                    <div class="ms-stat-card">
                        <div class="ms-stat-number"><?php echo count($statistics['country_breakdown']); ?></div>
                        <div class="ms-stat-label"><?php _e('Active Countries', 'morden-security'); ?></div>
                    </div>

                    <div class="ms-stat-card">
                        <div class="ms-stat-number"><?php echo count($statistics['blocked_countries']); ?></div>
                        <div class="ms-stat-label"><?php _e('Blocked Countries', 'morden-security'); ?></div>
                    </div>

                    <div class="ms-stat-card">
                        <div class="ms-stat-number"><?php echo count($statistics['top_threats']); ?></div>
                        <div class="ms-stat-label"><?php _e('High-Risk Countries', 'morden-security'); ?></div>
                    </div>
                </div>

                <div class="ms-chart-container">
                    <h3><?php _e('Traffic by Country', 'morden-security'); ?></h3>
                    <div class="ms-chart-canvas-wrapper">
                        <canvas id="countryTrafficChart"></canvas>
                    </div>
                </div>
            </div>

            <div class="ms-dashboard-side">
                <div class="ms-table-container">
                    <h3><?php _e('Top Threat Countries', 'morden-security'); ?></h3>
                    <table class="wp-list-table widefat fixed striped">
                        <thead>
                            <tr>
                                <th><?php _e('Country', 'morden-security'); ?></th>
                                <th><?php _e('Threat Score', 'morden-security'); ?></th>
                                <th><?php _e('Actions', 'morden-security'); ?></th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($statistics['top_threats'] as $country): ?>
                            <tr>
                                <td>
                                    <span class="ms-country-flag"><?php echo $this->getCountryFlag($country['code']); ?></span>
                                    <strong><?php echo esc_html($country['name']); ?></strong>
                                </td>
                                <td>
                                    <span class="ms-threat-score ms-score-<?php echo $this->getThreatScoreClass($country['threat_score']); ?>">
                                        <?php echo number_format($country['threat_score']); ?>
                                    </span>
                                </td>
                                <td>
                                    <?php if (!in_array($country['code'], array_column($statistics['blocked_countries'], 'code'))): ?>
                                        <button class="button button-small ms-block-country"
                                                data-country="<?php echo esc_attr($country['code']); ?>">
                                            <?php _e('Block', 'morden-security'); ?>
                                        </button>
                                    <?php else: ?>
                                        <button class="button button-small ms-unblock-country"
                                                data-country="<?php echo esc_attr($country['code']); ?>">
                                            <?php _e('Unblock', 'morden-security'); ?>
                                        </button>
                                    <?php endif; ?>
                                </td>
                            </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
        <?php
    }

    private function renderBlockedCountriesTab(array $blockedCountries, array $highRiskCountries): void
    {
        ?>
        <div class="ms-blocked-countries-grid">
            <?php if (empty($blockedCountries)): ?>
                <p><?php _e('No countries are currently blocked.', 'morden-security'); ?></p>
            <?php else: ?>
                <?php foreach ($blockedCountries as $country): ?>
                    <div class="ms-country-card">
                        <div class="ms-country-header">
                            <span class="ms-country-flag"><?php echo $this->getCountryFlag($country['code']); ?></span>
                            <strong><?php echo esc_html($country['name']); ?></strong>
                        </div>
                        <div class="ms-country-info">
                            <span class="ms-country-code">(<?php echo esc_html($country['code']); ?>)</span>
                            <span class="ms-risk-level ms-risk-high">
                                <?php _e('Blocked', 'morden-security'); ?>
                            </span>
                        </div>
                        <div class="ms-country-actions">
                            <button class="button button-small ms-unblock-country"
                                    data-country="<?php echo esc_attr($country['code']); ?>">
                                <?php _e('Unblock', 'morden-security'); ?>
                            </button>
                        </div>
                    </div>
                <?php endforeach; ?>
            <?php endif; ?>
        </div>

        <div class="ms-high-risk-countries">
            <h3><?php _e('High-Risk Countries', 'morden-security'); ?></h3>
            <p class="description">
                <?php _e('These countries are identified as high-risk based on security intelligence.', 'morden-security'); ?>
            </p>

            <div class="ms-risk-countries-grid">
                <?php foreach ($highRiskCountries as $country): ?>
                    <div class="ms-risk-country-card">
                        <div class="ms-country-header">
                            <span class="ms-country-flag"><?php echo $this->getCountryFlag($country['code']); ?></span>
                            <strong><?php echo esc_html($country['name']); ?></strong>
                        </div>
                        <div class="ms-risk-info">
                            <span class="ms-risk-level ms-risk-<?php echo esc_attr($country['risk_level']); ?>">
                                <?php echo esc_html(ucfirst($country['risk_level'])); ?> Risk
                            </span>
                        </div>
                        <div class="ms-country-actions">
                            <?php if (!$country['is_blocked']): ?>
                                <button class="button button-small ms-block-country"
                                        data-country="<?php echo esc_attr($country['code']); ?>">
                                    <?php _e('Block', 'morden-security'); ?>
                                </button>
                            <?php else: ?>
                                <span class="ms-status-blocked"><?php _e('Blocked', 'morden-security'); ?></span>
                            <?php endif; ?>
                        </div>
                    </div>
                <?php endforeach; ?>
            </div>
        </div>
        <?php
    }

    private function getCountryFlag(string $countryCode): string
    {
        if (strlen($countryCode) !== 2) {
            return '🏳️';
        }

        $flagOffset = 0x1F1E6;
        $asciiOffset = ord('A');
        $firstChar = $flagOffset + ord($countryCode[0]) - $asciiOffset;
        $secondChar = $flagOffset + ord($countryCode[1]) - $asciiOffset;

        return mb_chr($firstChar) . mb_chr($secondChar);
    }

    private function getThreatScoreClass(int $score): string
    {
        if ($score >= 500) return 'critical';
        if ($score >= 200) return 'high';
        if ($score >= 50) return 'medium';
        return 'low';
    }
}