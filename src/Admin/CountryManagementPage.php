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
        <div class="wrap">
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
        <div class="ms-country-overview">
            <div class="ms-country-stats">
                <h3><?php _e('Country Statistics', 'morden-security'); ?></h3>

                <div class="ms-stats-grid">
                    <div class="ms-stat-box">
                        <div class="ms-stat-number"><?php echo count($statistics['country_breakdown']); ?></div>
                        <div class="ms-stat-label"><?php _e('Active Countries', 'morden-security'); ?></div>
                    </div>

                    <div class="ms-stat-box">
                        <div class="ms-stat-number"><?php echo count($statistics['blocked_countries']); ?></div>
                        <div class="ms-stat-label"><?php _e('Blocked Countries', 'morden-security'); ?></div>
                    </div>

                    <div class="ms-stat-box">
                        <div class="ms-stat-number"><?php echo count($statistics['top_threats']); ?></div>
                        <div class="ms-stat-label"><?php _e('High-Risk Countries', 'morden-security'); ?></div>
                    </div>
                </div>
            </div>

            <div class="ms-country-breakdown">
                <h3><?php _e('Traffic by Country', 'morden-security'); ?></h3>
                <div class="ms-table-container">
                    <table class="wp-list-table widefat fixed striped">
                        <thead>
                            <tr>
                                <th><?php _e('Country', 'morden-security'); ?></th>
                                <th><?php _e('Total Requests', 'morden-security'); ?></th>
                                <th><?php _e('Blocked Requests', 'morden-security'); ?></th>
                                <th><?php _e('Block Rate', 'morden-security'); ?></th>
                                <th><?php _e('Threat Score', 'morden-security'); ?></th>
                                <th><?php _e('Actions', 'morden-security'); ?></th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($statistics['country_breakdown'] as $country): ?>
                            <tr>
                                <td>
                                    <span class="ms-country-flag"><?php echo $this->getCountryFlag($country['code']); ?></span>
                                    <strong><?php echo esc_html($country['name']); ?></strong>
                                    <span class="ms-country-code">(<?php echo esc_html($country['code']); ?>)</span>
                                </td>
                                <td><?php echo number_format($country['total_requests']); ?></td>
                                <td><?php echo number_format($country['blocked_requests']); ?></td>
                                <td>
                                    <?php
                                    $blockRate = $country['total_requests'] > 0 ?
                                        ($country['blocked_requests'] / $country['total_requests']) * 100 : 0;
                                    echo number_format($blockRate, 1) . '%';
                                    ?>
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
        <div class="ms-blocked-countries">

            <div class="ms-current-blocks">
                <h3><?php _e('Currently Blocked Countries', 'morden-security'); ?></h3>
                <?php if (empty($blockedCountries)): ?>
                    <p><?php _e('No countries are currently blocked.', 'morden-security'); ?></p>
                <?php else: ?>
                    <table class="wp-list-table widefat fixed striped">
                        <thead>
                            <tr>
                                <th><?php _e('Country', 'morden-security'); ?></th>
                                <th><?php _e('Blocked Date', 'morden-security'); ?></th>
                                <th><?php _e('Risk Level', 'morden-security'); ?></th>
                                <th><?php _e('Actions', 'morden-security'); ?></th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($blockedCountries as $country): ?>
                            <tr>
                                <td>
                                    <span class="ms-country-flag"><?php echo $this->getCountryFlag($country['code']); ?></span>
                                    <strong><?php echo esc_html($country['name']); ?></strong>
                                    <span class="ms-country-code">(<?php echo esc_html($country['code']); ?>)</span>
                                </td>
                                <td><?php echo date('Y-m-d H:i:s', time()); ?></td>
                                <td>
                                    <span class="ms-risk-level ms-risk-high">
                                        <?php _e('High', 'morden-security'); ?>
                                    </span>
                                </td>
                                <td>
                                    <button class="button button-small ms-unblock-country"
                                            data-country="<?php echo esc_attr($country['code']); ?>">
                                        <?php _e('Unblock', 'morden-security'); ?>
                                    </button>
                                </td>
                            </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
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
