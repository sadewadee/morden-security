<?php

namespace MordenSecurity\API\Endpoints;

use MordenSecurity\Core\SecurityCore;

class BotDetectionEndpoint {
    private $securityCore;

    public function __construct(SecurityCore $securityCore) {
        $this->securityCore = $securityCore;
    }

    public function register_routes(): void {
        add_action('wp_ajax_ms_get_bot_detection_stats', [$this, 'get_bot_detection_stats']);
    }

    public function get_bot_detection_stats(): void {
        check_ajax_referer('ms_admin_nonce', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error('Permission denied', 403);
        }

        $stats = $this->securityCore->getBotDetectionStats();

        wp_send_json_success($stats);
    }
}
