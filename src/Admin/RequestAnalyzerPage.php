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
            <h3><?php _e('Traffic Monitor', 'morden-security'); ?></h3>
            <table class="wp-list-table widefat fixed striped">
                <thead>
                    <tr>
                        <th><?php _e('Date', 'morden-security'); ?></th>
                        <th><?php _e('Method', 'morden-security'); ?></th>
                        <th><?php _e('URI', 'morden-security'); ?></th>
                        <th><?php _e('IP', 'morden-security'); ?></th>
                        <th><?php _e('User Agent', 'morden-security'); ?></th>
                        <th><?php _e('Referrer', 'morden-security'); ?></th>
                        <th><?php _e('Processing Time', 'morden-security'); ?></th>
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
                            $requestMethod = $context['request_method'] ?? '-';
                            $referrer = $context['referrer'] ?? '-';
                            $processingTime = isset($context['processing_time']) ? number_format($context['processing_time'], 4) . 's' : '-';
                            ?>
                            <tr>
                                <td><?php echo esc_html(date('Y-m-d H:i:s', strtotime($event['created_at']))); ?></td>
                                <td><?php echo esc_html($requestMethod); ?></td>
                                <td><?php echo esc_html($event['request_uri']); ?></td>
                                <td><code><?php echo esc_html($event['ip_address']); ?></code></td>
                                <td><?php echo esc_html($event['user_agent']); ?></td>
                                <td><?php echo esc_html($referrer); ?></td>
                                <td><?php echo esc_html($processingTime); ?></td>
                            </tr>
                        <?php endforeach; ?>
                    <?php endif; ?>
                </tbody>
            </table>
        </div>
        <?php
    }
}
