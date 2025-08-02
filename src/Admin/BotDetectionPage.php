<?php

namespace MordenSecurity\Admin;

use MordenSecurity\Core\LoggerSQLite;
use MordenSecurity\Core\BotDetection;

if (!defined('ABSPATH')) {
    exit;
}

class BotDetectionPage
{
    private LoggerSQLite $logger;
    private BotDetection $botDetection;

    public function __construct(LoggerSQLite $logger)
    {
        $this->logger = $logger;
        $this->botDetection = new BotDetection($logger);
    }

    public function render(): void
    {
        $this->handleWhitelistSubmission();

        $activeTab = sanitize_key($_GET['tab'] ?? 'overview');
        $botEvents = $this->getBotEvents();
        $statistics = $this->getBotStatistics();

        ?>
        <div class="wrap">
            <h1><?php _e('Bot Detection', 'morden-security'); ?></h1>

            <nav class="nav-tab-wrapper">
                <a href="?page=morden-security-bots&tab=overview"
                   class="nav-tab <?php echo $activeTab === 'overview' ? 'nav-tab-active' : ''; ?>">
                    <?php _e('Overview', 'morden-security'); ?>
                </a>
                <a href="?page=morden-security-bots&tab=detected"
                   class="nav-tab <?php echo $activeTab === 'detected' ? 'nav-tab-active' : ''; ?>">
                    <?php _e('Detected Bots', 'morden-security'); ?>
                </a>
                <a href="?page=morden-security-bots&tab=whitelist"
                   class="nav-tab <?php echo $activeTab === 'whitelist' ? 'nav-tab-active' : ''; ?>">
                    <?php _e('Bot Whitelist', 'morden-security'); ?>
                </a>
            </nav>

            <div class="tab-content">
                <?php
                switch ($activeTab) {
                    case 'overview':
                        $this->renderOverviewTab($statistics);
                        break;
                    case 'detected':
                        $this->renderDetectedBotsTab($botEvents);
                        break;
                    case 'whitelist':
                        $this->renderWhitelistTab();
                        break;
                }
                ?>
            </div>
        </div>
        <?php
    }

    private function handleWhitelistSubmission(): void
    {
        if (isset($_POST['ms_bot_whitelist_nonce']) && wp_verify_nonce($_POST['ms_bot_whitelist_nonce'], 'ms_add_bot_whitelist')) {
            $pattern = sanitize_text_field($_POST['bot_pattern']);
            $notes = sanitize_text_field($_POST['bot_notes']);

            if (!empty($pattern)) {
                $this->logger->addBotWhitelistRule([
                    'user_agent_pattern' => $pattern,
                    'notes' => $notes,
                    'created_by' => get_current_user_id()
                ]);
            }
        }

        if (isset($_GET['action'], $_GET['bot_id'], $_GET['_wpnonce']) &&
            $_GET['action'] === 'remove_bot_whitelist' &&
            wp_verify_nonce($_GET['_wpnonce'], 'ms_remove_bot_whitelist_' . $_GET['bot_id'])) {

            $botId = (int) $_GET['bot_id'];
            $this->logger->removeBotWhitelistRule($botId);
        }
    }

    private function renderOverviewTab(array $statistics): void
    {
        ?>
        <div class="ms-bot-overview">
            <div class="ms-bot-stats-grid">
                <div class="ms-bot-stat-card">
                    <div class="ms-stat-number"><?php echo number_format($statistics['total_bots']); ?></div>
                    <div class="ms-stat-label"><?php _e('Total Bot Detections', 'morden-security'); ?></div>
                </div>

                <div class="ms-bot-stat-card">
                    <div class="ms-stat-number"><?php echo number_format($statistics['malicious_bots']); ?></div>
                    <div class="ms-stat-label"><?php _e('Malicious Bots', 'morden-security'); ?></div>
                </div>

                <div class="ms-bot-stat-card">
                    <div class="ms-stat-number"><?php echo number_format($statistics['good_bots']); ?></div>
                    <div class="ms-stat-label"><?php _e('Good Bots', 'morden-security'); ?></div>
                </div>

                <div class="ms-bot-stat-card">
                    <div class="ms-stat-number"><?php echo number_format($statistics['blocked_bots']); ?></div>
                    <div class="ms-stat-label"><?php _e('Blocked Bots', 'morden-security'); ?></div>
                </div>
            </div>

            <div class="ms-dashboard-columns">
                <div class="ms-dashboard-main">
                    <div class="ms-bot-charts">
                        <div class="ms-chart-container">
                            <h3><?php _e('Bot Detection Trends (24h)', 'morden-security'); ?></h3>
                            <div class="ms-chart-canvas-wrapper">
                                <canvas id="botTrendsChart"></canvas>
                            </div>
                        </div>

                        <div class="ms-chart-container">
                            <h3><?php _e('Bot Types Distribution', 'morden-security'); ?></h3>
                            <div class="ms-chart-canvas-wrapper">
                                <canvas id="botTypesChart"></canvas>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="ms-dashboard-side">
                    <div class="ms-top-bot-ips">
                        <h3><?php _e('Top Bot IP Addresses', 'morden-security'); ?></h3>
                        <table class="wp-list-table widefat fixed striped">
                            <thead>
                                <tr>
                                    <th><?php _e('IP Address', 'morden-security'); ?></th>
                                    <th><?php _e('Bot Type', 'morden-security'); ?></th>
                                    <th><?php _e('Detection Count', 'morden-security'); ?></th>
                                    <th><?php _e('Last Seen', 'morden-security'); ?></th>
                                    <th><?php _e('Status', 'morden-security'); ?></th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($statistics['top_bot_ips'] as $botIP): ?>
                                <tr>
                                    <td><code><?php echo esc_html($botIP['ip_address']); ?></code></td>
                                    <td>
                                        <span class="ms-bot-type ms-bot-<?php echo esc_attr($botIP['type']); ?>">
                                            <?php echo esc_html(ucfirst(str_replace('_', ' ', $botIP['type']))); ?>
                                        </span>
                                    </td>
                                    <td><?php echo number_format($botIP['count']); ?></td>
                                    <td><?php echo esc_html(human_time_diff($botIP['last_seen'], time()) . ' ago'); ?></td>
                                    <td>
                                        <?php if ($botIP['is_blocked']): ?>
                                            <span class="ms-status-blocked"><?php _e('Blocked', 'morden-security'); ?></span>
                                        <?php else: ?>
                                            <span class="ms-status-allowed"><?php _e('Allowed', 'morden-security'); ?></span>
                                        <?php endif; ?>
                                    </td>
                                </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>
        <?php
    }

    private function renderDetectedBotsTab(array $botEvents): void
    {
        ?>
        <div class="ms-detected-bots">
            <div class="tablenav top">
                <div class="alignleft actions">
                    <select name="filter-bot-type" id="filter-bot-type">
                        <option value=""><?php _e('All Bot Types', 'morden-security'); ?></option>
                        <option value="malicious_bot"><?php _e('Malicious', 'morden-security'); ?></option>
                        <option value="good_bot"><?php _e('Good', 'morden-security'); ?></option>
                        <option value="suspicious_bot"><?php _e('Suspicious', 'morden-security'); ?></option>
                    </select>
                    <button class="button action" id="filter-bots"><?php _e('Filter', 'morden-security'); ?></button>
                </div>
            </div>

            <table class="wp-list-table widefat fixed striped">
                <thead>
                    <tr>
                        <th><?php _e('Time', 'morden-security'); ?></th>
                        <th><?php _e('IP Address', 'morden-security'); ?></th>
                        <th><?php _e('User Agent', 'morden-security'); ?></th>
                        <th><?php _e('Bot Type', 'morden-security'); ?></th>
                        <th><?php _e('Confidence', 'morden-security'); ?></th>
                        <th><?php _e('Action Taken', 'morden-security'); ?></th>
                        <th><?php _e('Details', 'morden-security'); ?></th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($botEvents as $event): ?>
                    <tr>
                        <td><?php echo esc_html(date('Y-m-d H:i:s', $event['timestamp'])); ?></td>
                        <td><code><?php echo esc_html($event['ip_address']); ?></code></td>
                        <td class="ms-user-agent" title="<?php echo esc_attr($event['user_agent']); ?>">
                            <?php echo esc_html(substr($event['user_agent'], 0, 50) . '...'); ?>
                        </td>
                        <td>
                            <span class="ms-bot-type ms-bot-<?php echo esc_attr($event['bot_type']); ?>">
                                <?php echo esc_html(ucfirst(str_replace('_', ' ', $event['bot_type']))); ?>
                            </span>
                        </td>
                        <td>
                            <div class="ms-confidence-bar">
                                <div class="ms-confidence-fill" style="width: <?php echo $event['confidence']; ?>%"></div>
                                <span class="ms-confidence-text"><?php echo $event['confidence']; ?>%</span>
                            </div>
                        </td>
                        <td>
                            <span class="ms-action ms-action-<?php echo esc_attr($event['action']); ?>">
                                <?php echo esc_html(ucfirst($event['action'])); ?>
                            </span>
                        </td>
                        <td>
                            <button class="button button-small ms-view-bot-details"
                                    data-event-id="<?php echo esc_attr($event['id']); ?>">
                                <?php _e('View', 'morden-security'); ?>
                            </button>
                        </td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
        <?php
    }

    private function renderWhitelistTab(): void
    {
        $whitelistedBots = $this->logger->getBotWhitelistRules();

        ?>
        <div class="ms-bot-whitelist">
            <div class="ms-add-whitelist-form">
                <h3><?php _e('Add Bot to Whitelist', 'morden-security'); ?></h3>
                <form method="post" class="ms-whitelist-form">
                    <?php wp_nonce_field('ms_add_bot_whitelist', 'ms_bot_whitelist_nonce'); ?>

                    <table class="form-table">
                        <tr>
                            <th scope="row">
                                <label for="bot_pattern"><?php _e('User Agent Pattern', 'morden-security'); ?></label>
                            </th>
                            <td>
                                <input type="text" id="bot_pattern" name="bot_pattern" class="regular-text"
                                       placeholder="googlebot" required>
                                <p class="description">
                                    <?php _e('Enter a part of the User-Agent string to whitelist (e.g., "googlebot", "MyCustomCrawler"). Case-insensitive.', 'morden-security'); ?>
                                </p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row">
                                <label for="bot_notes"><?php _e('Notes', 'morden-security'); ?></label>
                            </th>
                            <td>
                                <input type="text" id="bot_notes" name="bot_notes" class="regular-text"
                                       placeholder="<?php _e('e.g., My friendly monitoring service', 'morden-security'); ?>">
                            </td>
                        </tr>
                    </table>

                    <?php submit_button(__('Add to Whitelist', 'morden-security')); ?>
                </form>
            </div>

            <div class="ms-whitelisted-bots">
                <h3><?php _e('Whitelisted Bots', 'morden-security'); ?></h3>
                <table class="wp-list-table widefat fixed striped">
                    <thead>
                        <tr>
                            <th><?php _e('User Agent Pattern', 'morden-security'); ?></th>
                            <th><?php _e('Notes', 'morden-security'); ?></th>
                            <th><?php _e('Added By', 'morden-security'); ?></th>
                            <th><?php _e('Added Date', 'morden-security'); ?></th>
                            <th><?php _e('Actions', 'morden-security'); ?></th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($whitelistedBots as $bot): ?>
                        <tr>
                            <td><code><?php echo esc_html($bot['user_agent_pattern']); ?></code></td>
                            <td><?php echo esc_html($bot['notes']); ?></td>
                            <td><?php echo esc_html(get_user_by('id', $bot['created_by'])->display_name ?? 'Unknown'); ?></td>
                            <td><?php echo esc_html(date('Y-m-d H:i:s', strtotime($bot['created_at']))); ?></td>
                            <td>
                                <a href="<?php echo wp_nonce_url(admin_url('admin.php?page=morden-security-bots&tab=whitelist&action=remove_bot_whitelist&bot_id=' . $bot['id']), 'ms_remove_bot_whitelist_' . $bot['id']); ?>"
                                   class="button button-small button-danger">
                                    <?php _e('Remove', 'morden-security'); ?>
                                </a>
                            </td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </div>
        <?php
    }

    private function getBotEvents(): array
    {
        $events = $this->logger->getRecentEvents(200, [
            'event_type' => 'bot_detected'
        ]);

        foreach ($events as &$event) {
            $context = json_decode($event['context'], true) ?? [];
            $event['bot_type'] = $context['type'] ?? 'unknown';
            $event['confidence'] = $context['confidence'] ?? 0;
            $event['action'] = $event['action_taken'] ?? 'unknown';
        }

        return $events;
    }

    private function getBotStatistics(): array
    {
        $events = $this->logger->getRecentEvents(1000);

        $stats = [
            'total_bots' => 0,
            'malicious_bots' => 0,
            'good_bots' => 0,
            'blocked_bots' => 0,
            'top_bot_ips' => []
        ];

        $botIPs = [];

        foreach ($events as $event) {
            if (strpos($event['event_type'], 'bot') !== false) {
                $stats['total_bots']++;

                $context = json_decode($event['context'], true) ?? [];
                $botType = $context['type'] ?? 'unknown';

                if ($botType === 'malicious_bot' || $botType === 'behavioral_block') {
                    $stats['malicious_bots']++;
                } elseif ($botType === 'good_bot') {
                    $stats['good_bots']++;
                }

                if ($event['action_taken'] === 'blocked') {
                    $stats['blocked_bots']++;
                }

                $ip = $event['ip_address'];
                if (!isset($botIPs[$ip])) {
                    $botIPs[$ip] = [
                        'ip_address' => $ip,
                        'type' => $botType,
                        'count' => 0,
                        'last_seen' => 0,
                        'is_blocked' => $event['action_taken'] === 'blocked'
                    ];
                }

                $botIPs[$ip]['count']++;
                $botIPs[$ip]['last_seen'] = max($botIPs[$ip]['last_seen'], $event['timestamp']);
            }
        }

        uasort($botIPs, fn($a, $b) => $b['count'] <=> $a['count']);
        $stats['top_bot_ips'] = array_slice($botIPs, 0, 10);

        return $stats;
    }
}