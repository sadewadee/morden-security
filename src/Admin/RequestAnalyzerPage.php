<?php

namespace MordenSecurity\Admin;

use MordenSecurity\Core\LoggerSQLite;
use MordenSecurity\Core\SecurityEventTypes;

class RequestAnalyzerPage
{
    private LoggerSQLite $logger;

    public function __construct(LoggerSQLite $logger)
    {
        $this->logger = $logger;
    }

    public function render(): void
    {
        $activeTab = $_GET['tab'] ?? 'live-traffic';
        ?>
        <div class="wrap ms-request-analyzer">
            <h1><?php _e('Request Analyzer', 'morden-security'); ?></h1>

            <div class="nav-tab-wrapper">
                <a href="?page=ms-request-analyzer&tab=live-traffic" class="nav-tab <?php echo $activeTab === 'live-traffic' ? 'nav-tab-active' : ''; ?>"><?php _e('Live Traffic', 'morden-security'); ?></a>
                <a href="?page=ms-request-analyzer&tab=info" class="nav-tab <?php echo $activeTab === 'info' ? 'nav-tab-active' : ''; ?>"><?php _e('Info', 'morden-security'); ?></a>
            </div>

            <div id="live-traffic" class="tab-content <?php echo $activeTab === 'live-traffic' ? 'active' : ''; ?>">
                <?php $this->renderLiveTrafficTab(); ?>
            </div>

            <div id="info" class="tab-content <?php echo $activeTab === 'info' ? 'active' : ''; ?>">
                <h3><?php _e('Info', 'morden-security'); ?></h3>
                <p><?php _e('Coming soon...', 'morden-security'); ?></p>
            </div>
        </div>
        <?php
    }

    private function renderLiveTrafficTab(): void
    {
        $recentEvents = $this->logger->getRecentEvents(100);
        ?>
        <div class="ms-live-traffic">
            <h3><?php _e('Live Traffic', 'morden-security'); ?></h3>
            <table class="wp-list-table widefat fixed striped">
                <thead>
                    <tr>
                        <th><?php _e('Date', 'morden-security'); ?></th>
                        <th><?php _e('Username', 'morden-security'); ?></th>
                        <th><?php _e('URI', 'morden-security'); ?></th>
                        <th><?php _e('IP', 'morden-security'); ?></th>
                        <th><?php _e('Hostname', 'morden-security'); ?></th>
                        <th><?php _e('User Agent', 'morden-security'); ?></th>
                        <th><?php _e('Description', 'morden-security'); ?></th>
                    </tr>
                </thead>
                <tbody>
                    <?php if (empty($recentEvents)) : ?>
                        <tr>
                            <td colspan="7"><?php _e('No traffic to display.', 'morden-security'); ?></td>
                        </tr>
                    <?php else : ?>
                        <?php foreach ($recentEvents as $event) : ?>
                            <?php
                            $context = json_decode($event['context'] ?? '', true);
                            $username = $context['username'] ?? '-';
                            $ip = $event['ip_address'];
                            $hostname = gethostbyaddr($ip);
                            $eventLabel = SecurityEventTypes::getLabel($event['event_type']);
                            $requestMethod = $context['request_method'] ?? '-';
                            $httpCode = $context['http_code'] ?? '-';
                            $country = $event['country_code'] ? esc_html($event['country_code']) : 'N/A';
                            $threatScore = $event['threat_score'] ?? 0;

                            $eventName = !empty($event['rule_name']) ? esc_html($event['rule_name']) : esc_html($eventLabel);
                            $ruleId = !empty($event['rule_identifier']) ? ' (' . esc_html($event['rule_identifier']) . ')' : '';

                            $description = sprintf(
                                "<strong>%s%s</strong><br>URL: %s<br>Method: %s<br>Country: %s<br>Score: %d",
                                $eventName,
                                $ruleId,
                                esc_html($event['request_uri']),
                                esc_html($requestMethod),
                                $country,
                                $threatScore
                            );
                            ?>
                            <tr>
                                <td><?php echo esc_html(date('Y-m-d H:i:s', $event['timestamp'])); ?></td>
                                <td><?php echo esc_html($username); ?></td>
                                <td><?php echo esc_html($event['request_uri']); ?></td>
                                <td><code><?php echo esc_html($ip); ?></code></td>
                                <td><?php echo esc_html($hostname); ?></td>
                                <td><?php echo esc_html($event['user_agent']); ?></td>
                                <td><?php echo $description; ?></td>
                            </tr>
                        <?php endforeach; ?>
                    <?php endif; ?>
                </tbody>
            </table>
        </div>
        <?php
    }
}
