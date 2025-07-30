<?php

namespace MordenSecurity\Admin;

use MordenSecurity\Core\LoggerSQLite;
use MordenSecurity\Core\SecurityCore;

if (!defined('ABSPATH')) {
    exit;
}

class AdminController
{
    private LoggerSQLite $logger;
    private SecurityCore $securityCore;
    private array $pages;

    public function __construct()
    {
        $this->logger = new LoggerSQLite();
        $this->securityCore = new SecurityCore();
        $this->initializePages();
        $this->registerHooks();
    }

    public function registerHooks(): void
    {
        add_action('admin_menu', [$this, 'addAdminMenus']);
        add_action('admin_enqueue_scripts', [$this, 'enqueueAdminAssets']);
        add_action('wp_ajax_ms_get_security_stats', [$this, 'handleSecurityStatsAjax']);
        add_action('wp_ajax_ms_block_ip', [$this, 'handleBlockIPAjax']);
        add_action('wp_ajax_ms_unblock_ip', [$this, 'handleUnblockIPAjax']);
        add_action('admin_init', [$this, 'handleSettingsUpdates']);
    }

    public function addAdminMenus(): void
    {
        add_menu_page(
            __('Morden Security', 'morden-security'),
            __('Morden Security', 'morden-security'),
            'manage_options',
            'morden-security',
            [$this, 'renderDashboard'],
            'dashicons-shield-alt',
            30
        );

        add_submenu_page(
            'morden-security',
            __('Dashboard', 'morden-security'),
            __('Dashboard', 'morden-security'),
            'manage_options',
            'morden-security',
            [$this, 'renderDashboard']
        );

        add_submenu_page(
            'morden-security',
            __('IP Management', 'morden-security'),
            __('IP Management', 'morden-security'),
            'manage_options',
            'morden-security-ips',
            [$this, 'renderIPManagement']
        );

        add_submenu_page(
            'morden-security',
            __('Bot Detection', 'morden-security'),
            __('Bot Detection', 'morden-security'),
            'manage_options',
            'morden-security-bots',
            [$this, 'renderBotDetection']
        );

        add_submenu_page(
            'morden-security',
            __('Settings', 'morden-security'),
            __('Settings', 'morden-security'),
            'manage_options',
            'morden-security-settings',
            [$this, 'renderSettings']
        );
    }

    public function enqueueAdminAssets(string $hook): void
    {
        if (strpos($hook, 'morden-security') === false) {
            return;
        }

        wp_enqueue_style(
            'ms-admin-dashboard',
            MS_PLUGIN_URL . 'assets/css/admin-dashboard.css',
            [],
            MS_PLUGIN_VERSION
        );

        wp_enqueue_script(
            'ms-admin-dashboard',
            MS_PLUGIN_URL . 'assets/js/admin-dashboard.js',
            ['jquery'],
            MS_PLUGIN_VERSION,
            true
        );

        wp_localize_script('ms-admin-dashboard', 'msAdmin', [
            'ajaxUrl' => admin_url('admin-ajax.php'),
            'nonce' => wp_create_nonce('ms_admin_nonce'),
            'strings' => [
                'confirmBlock' => __('Are you sure you want to block this IP?', 'morden-security'),
                'confirmUnblock' => __('Are you sure you want to unblock this IP?', 'morden-security'),
                'error' => __('An error occurred. Please try again.', 'morden-security')
            ]
        ]);
    }

    public function renderDashboard(): void
    {
        $dashboard = new Dashboard($this->logger, $this->securityCore);
        $dashboard->render();
    }

    public function renderIPManagement(): void
    {
        $ipManagement = new IPManagementPage($this->logger);
        $ipManagement->render();
    }

    public function renderBotDetection(): void
    {
        $botDetection = new BotDetectionPage($this->logger);
        $botDetection->render();
    }

    public function renderSettings(): void
    {
        $settings = new Settings();
        $settings->render();
    }

    public function handleSecurityStatsAjax(): void
    {
        check_ajax_referer('ms_admin_nonce', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_die(__('Insufficient permissions', 'morden-security'));
        }

        $stats = $this->getSecurityStatistics();
        wp_send_json_success($stats);
    }

    public function handleBlockIPAjax(): void
    {
        check_ajax_referer('ms_admin_nonce', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_die(__('Insufficient permissions', 'morden-security'));
        }

        $ipAddress = sanitize_text_field($_POST['ip_address'] ?? '');
        $reason = sanitize_text_field($_POST['reason'] ?? 'manual_block');
        $duration = sanitize_text_field($_POST['duration'] ?? 'permanent');

        if (empty($ipAddress)) {
            wp_send_json_error(__('Invalid IP address', 'morden-security'));
        }

        $ruleData = [
            'ip_address' => $ipAddress,
            'rule_type' => 'blacklist',
            'block_duration' => $duration,
            'reason' => $reason,
            'block_source' => 'manual',
            'created_by' => get_current_user_id(),
            'threat_score' => 0,
            'notes' => "Manually blocked by " . wp_get_current_user()->user_login
        ];

        $success = $this->logger->addIPRule($ruleData);

        if ($success) {
            wp_send_json_success(__('IP address blocked successfully', 'morden-security'));
        } else {
            wp_send_json_error(__('Failed to block IP address', 'morden-security'));
        }
    }

    public function handleUnblockIPAjax(): void
    {
        check_ajax_referer('ms_admin_nonce', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_die(__('Insufficient permissions', 'morden-security'));
        }

        $ipAddress = sanitize_text_field($_POST['ip_address'] ?? '');

        if (empty($ipAddress)) {
            wp_send_json_error(__('Invalid IP address', 'morden-security'));
        }

        $success = $this->unblockIP($ipAddress);

        if ($success) {
            wp_send_json_success(__('IP address unblocked successfully', 'morden-security'));
        } else {
            wp_send_json_error(__('Failed to unblock IP address', 'morden-security'));
        }
    }

    public function handleSettingsUpdates(): void
    {
        if (!isset($_POST['ms_settings_nonce']) ||
            !wp_verify_nonce($_POST['ms_settings_nonce'], 'ms_save_settings')) {
            return;
        }

        if (!current_user_can('manage_options')) {
            return;
        }

        $settingsToUpdate = [
            'ms_firewall_enabled' => 'bool',
            'ms_auto_blocking_enabled' => 'bool',
            'ms_bot_detection_enabled' => 'bool',
            'ms_logging_enabled' => 'bool',
            'ms_temp_block_duration' => 'int',
            'ms_perm_block_threshold' => 'int',
            'ms_bot_challenge_threshold' => 'int',
            'ms_bot_block_threshold' => 'int'
        ];

        foreach ($settingsToUpdate as $setting => $type) {
            if (isset($_POST[$setting])) {
                $value = $_POST[$setting];

                switch ($type) {
                    case 'bool':
                        $value = (bool) $value;
                        break;
                    case 'int':
                        $value = (int) $value;
                        break;
                    default:
                        $value = sanitize_text_field($value);
                }

                update_option($setting, $value);
            }
        }

        add_action('admin_notices', function() {
            echo '<div class="notice notice-success"><p>' .
                 __('Settings saved successfully.', 'morden-security') .
                 '</p></div>';
        });
    }

    private function initializePages(): void
    {
        $this->pages = [
            'dashboard' => Dashboard::class,
            'ip_management' => IPManagementPage::class,
            'bot_detection' => BotDetectionPage::class,
            'settings' => Settings::class
        ];
    }

    private function getSecurityStatistics(): array
    {
        $recentEvents = $this->logger->getRecentEvents(1000);

        $stats = [
            'total_events' => count($recentEvents),
            'blocked_requests' => 0,
            'bot_detections' => 0,
            'firewall_blocks' => 0,
            'threat_level' => 'low',
            'top_threats' => [],
            'hourly_stats' => []
        ];

        $eventTypes = array_count_values(array_column($recentEvents, 'event_type'));

        $stats['blocked_requests'] = $eventTypes['request_blocked'] ?? 0;
        $stats['bot_detections'] = $eventTypes['bot_detected'] ?? 0;
        $stats['firewall_blocks'] = $eventTypes['firewall_block'] ?? 0;

        $stats['threat_level'] = $this->calculateThreatLevel($recentEvents);
        $stats['top_threats'] = $this->getTopThreats($recentEvents);
        $stats['hourly_stats'] = $this->getHourlyStatistics($recentEvents);

        return $stats;
    }

    private function calculateThreatLevel(array $events): string
    {
        $recentThreats = array_filter($events, function($event) {
            return $event['timestamp'] > time() - 3600 &&
                   in_array($event['event_type'], ['request_blocked', 'bot_detected', 'firewall_block']);
        });

        $threatCount = count($recentThreats);

        if ($threatCount > 50) return 'critical';
        if ($threatCount > 20) return 'high';
        if ($threatCount > 5) return 'medium';
        return 'low';
    }

    private function getTopThreats(array $events): array
    {
        $ipCounts = [];

        foreach ($events as $event) {
            if (in_array($event['event_type'], ['request_blocked', 'bot_detected', 'firewall_block'])) {
                $ip = $event['ip_address'];
                $ipCounts[$ip] = ($ipCounts[$ip] ?? 0) + 1;
            }
        }

        arsort($ipCounts);
        return array_slice($ipCounts, 0, 10, true);
    }

    private function getHourlyStatistics(array $events): array
    {
        $hourlyStats = array_fill(0, 24, ['blocked' => 0, 'allowed' => 0]);

        foreach ($events as $event) {
            $hour = (int) date('H', $event['timestamp']);

            if (in_array($event['event_type'], ['request_blocked', 'bot_detected', 'firewall_block'])) {
                $hourlyStats[$hour]['blocked']++;
            } else {
                $hourlyStats[$hour]['allowed']++;
            }
        }

        return $hourlyStats;
    }

    private function unblockIP(string $ipAddress): bool
    {
        try {
            $stmt = $this->logger->database->prepare('
                UPDATE ms_ip_rules
                SET is_active = 0,
                    updated_at = CURRENT_TIMESTAMP,
                    notes = COALESCE(notes, "") || " - Manually unblocked"
                WHERE ip_address = ? AND is_active = 1
            ');

            if ($stmt) {
                $stmt->bindValue(1, $ipAddress, SQLITE3_TEXT);
                $result = $stmt->execute();
                return $result !== false;
            }
        } catch (Exception $e) {
            error_log("MS: Failed to unblock IP {$ipAddress} - " . $e->getMessage());
        }

        return false;
    }
}
