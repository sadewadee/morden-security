<?php

namespace MordenSecurity\Admin;

use MordenSecurity\Core\LoggerSQLite;
use MordenSecurity\Core\SecurityCore;
use MordenSecurity\Admin\Dashboard;
use MordenSecurity\Admin\IPManagementPage;
use MordenSecurity\Admin\BotDetectionPage;
use MordenSecurity\Admin\CountryManagementPage;
use MordenSecurity\Admin\Settings;
use MordenSecurity\Utils\IPUtils;

if (!defined('ABSPATH')) {
    exit;
}

class AdminController
{
    private LoggerSQLite $logger;
    private SecurityCore $securityCore;
    private Settings $settings;

    public function __construct()
    {
        $this->logger = new LoggerSQLite();
        $this->securityCore = new SecurityCore();
        $this->settings = new Settings();
        $this->registerHooks();
    }

    private function registerHooks(): void
    {
        add_action('admin_menu', [$this, 'addAdminMenus']);
        add_action('admin_enqueue_scripts', [$this, 'enqueueAdminAssets']);
        add_action('wp_ajax_ms_get_security_stats', [$this, 'handleSecurityStatsAjax']);
        add_action('wp_ajax_ms_block_ip', [$this, 'handleBlockIPAjax']);
        add_action('wp_ajax_ms_get_ip_logs', [$this, 'handleGetIPLogsAjax']);
        add_action('wp_ajax_ms_unblock_ip', [$this, 'handleUnblockIPAjax']);
        add_action('init', [$this, 'initializeAjaxHandlers']);
    }

    public function addAdminMenus(): void
    {
        add_menu_page(
            'Morden Security',
            'Morden Security',
            'manage_options',
            'morden-security',
            [$this, 'renderDashboard'],
            'dashicons-shield-alt',
            30
        );

        add_submenu_page(
            'morden-security',
            'Dashboard',
            'Dashboard',
            'manage_options',
            'morden-security',
            [$this, 'renderDashboard']
        );

        add_submenu_page(
            'morden-security',
            'IP Management',
            'IP Management',
            'manage_options',
            'morden-security-ips',
            [$this, 'renderIPManagement']
        );

        add_submenu_page(
            'morden-security',
            'Bot Detection',
            'Bot Detection',
            'manage_options',
            'morden-security-bots',
            [$this, 'renderBotDetection']
        );

        add_submenu_page(
            'morden-security',
            'Country Management',
            'Country Management',
            'manage_options',
            'morden-security-countries',
            [$this, 'renderCountryManagement']
        );
        add_submenu_page(
            'morden-security',
            'Settings',
            'Settings',
            'manage_options',
            'morden-security-settings',
            [$this, 'renderSettings']
        );
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

    public function renderCountryManagement(): void
    {
        $countryManagement = new CountryManagementPage($this->logger);
        $countryManagement->render();
    }

    public function renderSettings(): void
    {
        $this->settings->render();
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
            'nonce' => wp_create_nonce('ms_admin_nonce')
        ]);
    }

    public function handleSecurityStatsAjax(): void
    {
        check_ajax_referer('ms_admin_nonce', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error(__('Insufficient permissions', 'morden-security'), 403);
        }

        $stats = $this->logger->getSecurityStats();
        wp_send_json_success($stats);
    }

    public function handleGetIPLogsAjax(): void
    {
        check_ajax_referer('ms_admin_nonce', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error(__('Insufficient permissions', 'morden-security'), 403);
        }

        $ipAddress = sanitize_text_field($_POST['ip_address'] ?? '');

        if (empty($ipAddress) || !\MordenSecurity\Utils\IPUtils::isValidIP($ipAddress)) {
            wp_send_json_error(__('Invalid IP address provided.', 'morden-security'), 400);
        }

        $logs = $this->logger->getRecentEvents(100, ['ip_address' => $ipAddress]);

        wp_send_json_success($logs);
    }

    public function handleBlockIPAjax(): void
    {
        check_ajax_referer('ms_admin_nonce', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error(__('Insufficient permissions', 'morden-security'), 403);
        }

        $ipAddress = sanitize_text_field($_POST['ip_address'] ?? '');
        if (!\MordenSecurity\Utils\IPUtils::isValidIP($ipAddress)) {
            wp_send_json_error(__('Invalid IP address provided.', 'morden-security'));
        }

        $blocker = new \MordenSecurity\Modules\IPManagement\IPBlocker($this->logger);
        $blockData = [
            'reason' => sanitize_text_field($_POST['reason'] ?? 'Manual block from admin'),
            'duration' => sanitize_key($_POST['duration'] ?? 'permanent'),
            'source' => 'admin_ui'
        ];

        if ($blocker->addBlock($ipAddress, $blockData)) {
            wp_send_json_success(__('IP address blocked successfully.', 'morden-security'));
        } else {
            wp_send_json_error(__('Failed to block IP address.', 'morden-security'));
        }
    }

    public function handleUnblockIPAjax(): void
    {
        check_ajax_referer('ms_admin_nonce', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error(__('Insufficient permissions', 'morden-security'), 403);
        }

        $ipAddress = sanitize_text_field($_POST['ip_address'] ?? '');
        if (!\MordenSecurity\Utils\IPUtils::isValidIP($ipAddress)) {
            wp_send_json_error(__('Invalid IP address provided.', 'morden-security'));
        }

        $blocker = new \MordenSecurity\Modules\IPManagement\IPBlocker($this->logger);
        if ($blocker->removeBlock($ipAddress)) {
            wp_send_json_success(__('IP address unblocked successfully.', 'morden-security'));
        } else {
            wp_send_json_error(__('Failed to unblock IP address. It may not be blocked.', 'morden-security'));
        }
    }

    public function initializeAjaxHandlers(): void {
    add_action('wp_ajax_ms_get_ip_details', [$this, 'handleGetIPDetails']);
}

public function handleGetIPDetails(): void {
    // Verify nonce
    if (!wp_verify_nonce($_POST['nonce'] ?? '', 'ms_admin_nonce')) {
        wp_die(json_encode([
            'success' => false,
            'data' => 'Security check failed'
        ]));
    }

    $ipAddress = sanitize_text_field($_POST['ip_address'] ?? '');

    if (empty($ipAddress)) {
        wp_send_json_error('IP address is required');
        return;
    }

    if (!filter_var($ipAddress, FILTER_VALIDATE_IP)) {
        wp_send_json_error('Invalid IP address format');
        return;
    }

    try {
        $ipDetails = IPUtils::getIPDetails($ipAddress);

        if ($ipDetails['success']) {
            $logger = new LoggerSQLite();
            $events = $logger->getEventsByIP($ipAddress, 50);
            $eventCount = $logger->getRecentEvents(1000, ['ip_address' => $ipAddress]);

            $firstSeenTimestamp = !empty($events) ? $events[count($events) - 1]['timestamp'] : time();
            $lastSeenTimestamp = !empty($events) ? $events[0]['timestamp'] : time();

            $response = [
                'ip_address' => $ipAddress,
                'country_code' => $ipDetails['country_code'] ?? 'UNKNOWN',
                'country' => $ipDetails['country_name'] ?? 'Unknown',
                'city' => $ipDetails['city'] ?? 'Unknown',
                'isp' => $ipDetails['isp'] ?? 'Unknown',
                'region' => $ipDetails['region'] ?? 'Unknown',
                'timezone' => $ipDetails['timezone'] ?? 'Unknown',
                'total_events' => $eventCount,
                'threat_score' => $this->calculateThreatScore($events),
                'recent_events' => array_slice($events, 0, 10),
                'first_seen' => $this->formatTimestamp($firstSeenTimestamp),
                'last_seen' => $this->formatTimestamp($lastSeenTimestamp)
            ];

            wp_send_json_success($response);
        } else {
            wp_send_json_error($ipDetails['error'] ?? 'Failed to get IP details');
        }

    } catch (Exception $e) {
        error_log('MS IP Details Error: ' . $e->getMessage());
        wp_send_json_error('Internal server error');
    }
}

private function calculateThreatScore(array $events): int {
    if (empty($events)) {
        return 0;
    }

    $score = 0;
    foreach ($events as $event) {
        $severity = $event['severity'] ?? 1;
        $score += $severity;
    }

    return min(100, $score);
}

private function formatTimestamp(int $timestamp): string {
    if ($timestamp <= 0) {
        return 'Never';
    }

    return wp_date('d-m-y H:i:s', $timestamp);
}


private function getRelativeTime(int $timestamp): string {
    if ($timestamp <= 0) {
        return 'Never';
    }

    $diff = time() - $timestamp;

    if ($diff < 60) {
        return $diff . ' seconds ago';
    } elseif ($diff < 3600) {
        return floor($diff / 60) . ' minutes ago';
    } elseif ($diff < 86400) {
        return floor($diff / 3600) . ' hours ago';
    } elseif ($diff < 2592000) {
        return floor($diff / 86400) . ' days ago';
    } else {
        return wp_date('d M Y', $timestamp);
    }
}

}
