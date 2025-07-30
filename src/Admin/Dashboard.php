<?php

namespace MordenSecurity\Admin;

use MordenSecurity\Core\LoggerSQLite;
use MordenSecurity\Core\SecurityCore;

if (!defined('ABSPATH')) {
    exit;
}

class Dashboard
{
    private LoggerSQLite $logger;
    private SecurityCore $securityCore;

    public function __construct(LoggerSQLite $logger, SecurityCore $securityCore)
    {
        $this->logger = $logger;
        $this->securityCore = $securityCore;
    }

    public function render(): void
    {
        $stats = $this->getStatistics();
        $recentEvents = $this->logger->getRecentEvents(50);
        $securityStatus = $this->securityCore->getSecurityStatus();

        ?>
        <div class="wrap">
            <h1><?php _e('Morden Security Dashboard', 'morden-security'); ?></h1>

            <div class="ms-dashboard-grid">
                <?php $this->renderStatCards($stats); ?>
                <?php $this->renderThreatLevelCard($securityStatus); ?>
                <?php $this->renderRecentEventsTable($recentEvents); ?>
                <?php $this->renderTopThreatsTable($stats['top_threats']); ?>
            </div>
        </div>
        <?php
    }

    private function renderStatCards(array $stats): void
    {
        ?>
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
        <?php
    }

    private function renderThreatLevelCard(array $securityStatus): void
    {
        $threatLevel = $securityStatus['threat_level'];
        $threatClass = "ms-threat-{$threatLevel}";

        ?>
        <div class="ms-threat-level-card <?php echo esc_attr($threatClass); ?>">
            <h3><?php _e('Current Threat Level', 'morden-security'); ?></h3>
            <div class="ms-threat-indicator">
                <span class="ms-threat-level"><?php echo esc_html(ucfirst($threatLevel)); ?></span>
                <div class="ms-threat-description">
                    <?php echo esc_html($this->getThreatDescription($threatLevel)); ?>
                </div>
            </div>
        </div>
        <?php
    }

    private function renderRecentEventsTable(array $events): void
    {
        ?>
        <div class="ms-recent-events">
            <h3><?php _e('Recent Security Events', 'morden-security'); ?></h3>
            <div class="ms-table-container">
                <table class="wp-list-table widefat fixed striped">
                    <thead>
                        <tr>
                            <th><?php _e('Time', 'morden-security'); ?></th>
                            <th><?php _e('Event Type', 'morden-security'); ?></th>
                            <th><?php _e('IP Address', 'morden-security'); ?></th>
                            <th><?php _e('Severity', 'morden-security'); ?></th>
                            <th><?php _e('Message', 'morden-security'); ?></th>
                            <th><?php _e('Action', 'morden-security'); ?></th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($events as $event): ?>
                        <tr>
                            <td><?php echo esc_html(date('H:i:s', $event['timestamp'])); ?></td>
                            <td>
                                <span class="ms-event-type ms-event-<?php echo esc_attr($event['event_type']); ?>">
                                    <?php echo esc_html(ucfirst(str_replace('_', ' ', $event['event_type']))); ?>
                                </span>
                            </td>
                            <td>
                                <code><?php echo esc_html($event['ip_address']); ?></code>
                                <div class="ms-country-flag">
                                    <?php echo esc_html($event['country_code'] ?? 'None'); ?>
                                </div>
                            </td>
                            <td>
                                <span class="ms-severity ms-severity-<?php echo esc_attr($event['severity']); ?>">
                                    <?php echo esc_html($this->getSeverityLabel($event['severity'])); ?>
                                </span>
                            </td>
                            <td><?php echo esc_html($event['message']); ?></td>
                            <td>
                                <?php if ($event['action_taken'] !== 'request_allowed'): ?>
                                <button class="button button-small ms-block-ip"
                                        data-ip="<?php echo esc_attr($event['ip_address']); ?>">
                                    <?php _e('Block IP', 'morden-security'); ?>
                                </button>
                                <?php endif; ?>
                            </td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </div>
        <?php
    }

    private function renderTopThreatsTable(array $topThreats): void
    {
        ?>
        <div class="ms-top-threats">
            <h3><?php _e('Top Threat Sources', 'morden-security'); ?></h3>
            <div class="ms-table-container">
                <table class="wp-list-table widefat fixed striped">
                    <thead>
                        <tr>
                            <th><?php _e('IP Address', 'morden-security'); ?></th>
                            <th><?php _e('Threat Count', 'morden-security'); ?></th>
                            <th><?php _e('Last Seen', 'morden-security'); ?></th>
                            <th><?php _e('Actions', 'morden-security'); ?></th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($topThreats as $ip => $count): ?>
                        <tr>
                            <td>
                                <code><?php echo esc_html($ip); ?></code>
                            </td>
                            <td>
                                <span class="ms-threat-count"><?php echo number_format($count); ?></span>
                            </td>
                            <td>
                                <?php echo esc_html($this->getLastSeenTime($ip)); ?>
                            </td>
                            <td>
                                <button class="button button-primary button-small ms-block-ip"
                                        data-ip="<?php echo esc_attr($ip); ?>">
                                    <?php _e('Block', 'morden-security'); ?>
                                </button>
                                <button class="button button-small ms-view-details"
                                        data-ip="<?php echo esc_attr($ip); ?>">
                                    <?php _e('Details', 'morden-security'); ?>
                                </button>
                            </td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </div>
        <?php
    }

    private function getStatistics(): array
    {
        $recentEvents = $this->logger->getRecentEvents(1000);

        $stats = [
            'total_events' => count($recentEvents),
            'blocked_requests' => 0,
            'bot_detections' => 0,
            'firewall_blocks' => 0,
            'top_threats' => []
        ];

        $eventTypes = array_count_values(array_column($recentEvents, 'event_type'));
        $ipCounts = [];

        $stats['blocked_requests'] = $eventTypes['request_blocked'] ?? 0;
        $stats['bot_detections'] = $eventTypes['bot_detected'] ?? 0;
        $stats['firewall_blocks'] = $eventTypes['firewall_block'] ?? 0;

        foreach ($recentEvents as $event) {
            if (in_array($event['event_type'], ['request_blocked', 'bot_detected', 'firewall_block'])) {
                $ip = $event['ip_address'];
                $ipCounts[$ip] = ($ipCounts[$ip] ?? 0) + 1;
            }
        }

        arsort($ipCounts);
        $stats['top_threats'] = array_slice($ipCounts, 0, 10, true);

        return $stats;
    }

    private function getThreatDescription(string $threatLevel): string
    {
        $descriptions = [
            'low' => __('System operating normally with minimal threats detected.', 'morden-security'),
            'medium' => __('Moderate threat activity. Enhanced monitoring recommended.', 'morden-security'),
            'high' => __('High threat activity detected. Review security settings.', 'morden-security'),
            'critical' => __('Critical threat level. Immediate attention required.', 'morden-security')
        ];

        return $descriptions[$threatLevel] ?? $descriptions['low'];
    }

    private function getSeverityLabel(int $severity): string
    {
        $labels = [
            1 => __('Info', 'morden-security'),
            2 => __('Low', 'morden-security'),
            3 => __('Medium', 'morden-security'),
            4 => __('High', 'morden-security')
        ];

        return $labels[$severity] ?? $labels[1];
    }

    private function getLastSeenTime(string $ip): string
    {
        $events = $this->logger->getRecentEvents(10, ['ip_address' => $ip]);

        if (empty($events)) {
            return __('Unknown', 'morden-security');
        }

        $lastSeen = $events[0]['timestamp'];
        return human_time_diff($lastSeen, time()) . ' ' . __('ago', 'morden-security');
    }
}
