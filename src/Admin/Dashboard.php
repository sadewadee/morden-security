<?php

namespace MordenSecurity\Admin;

use MordenSecurity\Core\LoggerSQLite;
use MordenSecurity\Core\SecurityCore;

class Dashboard {
    private $logger;
    private $securityCore;

    public function __construct(LoggerSQLite $logger, SecurityCore $securityCore) {
        $this->logger = $logger;
        $this->securityCore = $securityCore;
    }

    public function render(): void {
        $stats = $this->getStatistics();
        $recentEvents = $this->logger->getRecentEvents(50);
        $securityStatus = $this->securityCore->getSecurityStatus();
        ?>

        <div class="wrap ms-dashboard">
            <h1><?php _e('Morden Security Dashboard', 'morden-security'); ?></h1>

            <!-- Mobile-friendly alert for threat level -->
            <div class="ms-threat-level-card ms-threat-<?php echo esc_attr($securityStatus['threat_level']); ?>">
                <h3><?php _e('Current Threat Level', 'morden-security'); ?></h3>
                <div class="ms-threat-indicator">
                    <div class="ms-threat-level"><?php echo esc_html(ucfirst($securityStatus['threat_level'])); ?></div>
                    <div class="ms-threat-description">
                        <?php echo esc_html($securityStatus['description']); ?>
                    </div>
                </div>
            </div>

            <!-- Responsive stats grid -->
            <div class="ms-stat-cards">
                <div class="ms-stat-card blocked">
                    <div class="ms-stat-number"><?php echo number_format($stats['blocked_requests']); ?></div>
                    <div class="ms-stat-label"><?php _e('Blocked Requests', 'morden-security'); ?></div>
                </div>

                <div class="ms-stat-card bots">
                    <div class="ms-stat-number"><?php echo number_format($stats['bot_detections']); ?></div>
                    <div class="ms-stat-label"><?php _e('Bot Detections', 'morden-security'); ?></div>
                </div>

                <div class="ms-stat-card firewall">
                    <div class="ms-stat-number"><?php echo number_format($stats['firewall_blocks']); ?></div>
                    <div class="ms-stat-label"><?php _e('Firewall Blocks', 'morden-security'); ?></div>
                </div>

                <div class="ms-stat-card total">
                    <div class="ms-stat-number"><?php echo number_format($stats['total_events']); ?></div>
                    <div class="ms-stat-label"><?php _e('Total Events', 'morden-security'); ?></div>
                </div>
            </div>

            <div class="ms-dashboard-columns">
                <div class="ms-dashboard-main">
                    <div class="ms-recent-events">
                        <h3><?php _e('Recent Security Events', 'morden-security'); ?></h3>
                        <div class="ms-table-container">
                            <table class="wp-list-table widefat fixed striped">
                                <thead>
                                    <tr>
                                        <th style="width: 120px;"><?php _e('Time', 'morden-security'); ?></th>
                                        <th style="width: 100px;"><?php _e('IP Address', 'morden-security'); ?></th>
                                        <th style="width: 80px;"><?php _e('Type', 'morden-security'); ?></th>
                                        <th style="width: 60px;"><?php _e('Severity', 'morden-security'); ?></th>
                                        <th><?php _e('Message', 'morden-security'); ?></th>
                                        <th style="width: 100px;"><?php _e('Actions', 'morden-security'); ?></th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php if (empty($recentEvents)): ?>
                                        <tr>
                                            <td colspan="6" style="text-align: center; padding: 20px;">
                                                <?php _e('No recent security events found.', 'morden-security'); ?>
                                            </td>
                                        </tr>
                                    <?php else: ?>
                                        <?php foreach ($recentEvents as $event): ?>
                                            <tr>
                                                <td>
                                                    <span class="ms-timestamp" data-timestamp="<?php echo esc_attr($event['timestamp']); ?>">
                                                        <?php echo esc_html(date('M j, H:i', $event['timestamp'])); ?>
                                                    </span>
                                                </td>
                                                <td>
                                                    <span class="ms-ip-address"><?php echo esc_html($event['ip_address']); ?></span>
                                                    <div class="ms-country-flag"><?php echo esc_html($event['country_code'] ?? ''); ?></div>
                                                </td>
                                                <td>
                                                    <span class="ms-event-type ms-event-<?php echo esc_attr($event['event_type']); ?>">
                                                        <?php echo esc_html($event['event_type']); ?>
                                                    </span>
                                                </td>
                                                <td>
                                                    <span class="ms-severity ms-severity-<?php echo esc_attr($event['severity']); ?>">
                                                        <?php echo esc_html($this->getSeverityLabel($event['severity'])); ?>
                                                    </span>
                                                </td>
                                                <td class="ms-message">
                                                    <?php echo esc_html(wp_trim_words($event['message'], 10)); ?>
                                                </td>
                                                <td>
                                                    <button class="button button-small ms-view-details"
                                                            data-ip="<?php echo esc_attr($event['ip_address']); ?>">
                                                        <?php _e('Details', 'morden-security'); ?>
                                                    </button>
                                                </td>
                                            </tr>
                                        <?php endforeach; ?>
                                    <?php endif; ?>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
                <div class="ms-dashboard-side">
                    <div class="ms-top-threats">
                        <h3><?php _e('Top Threats', 'morden-security'); ?></h3>
                        <p><?php _e('Coming soon...', 'morden-security'); ?></p>
                    </div>
                </div>
            </div>
        </div>

        <?php
    }

    private function getStatistics(): array
    {
        $securityStats = $this->logger->getSecurityStats();

        $recentEvents = $this->logger->getRecentEvents(1000, ['since' => time() - 86400]);

        $stats = [
            'blocked_requests' => $securityStats['blocked_requests'] ?? 0,
            'bot_detections' => $securityStats['bot_detections'] ?? 0,
            'firewall_blocks' => $securityStats['firewall_blocks'] ?? 0,
            'total_events' => $securityStats['total_events'] ?? 0
        ];

        if ($stats['total_events'] === 0) {
            $stats['total_events'] = count($recentEvents);
            $stats['blocked_requests'] = count(array_filter($recentEvents, fn($e) => strpos($e['action_taken'] ?? '', 'block') !== false));
            $stats['bot_detections'] = count(array_filter($recentEvents, fn($e) => strpos($e['event_type'] ?? '', 'bot') !== false));
            $stats['firewall_blocks'] = count(array_filter($recentEvents, fn($e) => $e['event_type'] === 'firewall_block'));
        }

        return $stats;
    }

    private function getSeverityLabel(int $severity): string {
        $labels = [
            1 => __('Info', 'morden-security'),
            2 => __('Warning', 'morden-security'),
            3 => __('High', 'morden-security'),
            4 => __('Critical', 'morden-security')
        ];

        return $labels[$severity] ?? __('Unknown', 'morden-security');
    }
}
