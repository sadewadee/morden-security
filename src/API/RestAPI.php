<?php

namespace MordenSecurity\API;

use MordenSecurity\API\Endpoints\BotDetectionEndpoint;
use MordenSecurity\Core\SecurityCore;
use MordenSecurity\Core\LoggerSQLite;
use MordenSecurity\Utils\IPUtils;
use MordenSecurity\Utils\Validation;
use MordenSecurity\Core\AutoIPBlocker;

if (!defined('ABSPATH')) {
    exit;
}

class RestAPI
{
    private LoggerSQLite $logger;
    private AutoIPBlocker $autoBlocker;
    private BotDetectionEndpoint $botDetectionEndpoint;
    private string $namespace = 'morden-security/v1';

    public function __construct()
    {
        $this->logger = new LoggerSQLite();
        $this->autoBlocker = new AutoIPBlocker($this->logger);
        $this->botDetectionEndpoint = new BotDetectionEndpoint(new SecurityCore());
        $this->registerRoutes();
    }

    public function registerRoutes(): void
    {
        add_action('rest_api_init', [$this, 'registerEndpoints']);
        $this->botDetectionEndpoint->register_routes();
    }

    public function registerEndpoints(): void
    {
        register_rest_route($this->namespace, '/security-events', [
            'methods' => 'GET',
            'callback' => [$this, 'getSecurityEvents'],
            'permission_callback' => [$this, 'checkPermissions']
        ]);

        register_rest_route($this->namespace, '/ip-rules', [
            'methods' => 'GET',
            'callback' => [$this, 'getIPRules'],
            'permission_callback' => [$this, 'checkPermissions']
        ]);

        register_rest_route($this->namespace, '/ip-rules', [
            'methods' => 'POST',
            'callback' => [$this, 'addIPRule'],
            'permission_callback' => [$this, 'checkPermissions']
        ]);

        register_rest_route($this->namespace, '/ip-rules/(?P<ip>[^/]+)', [
            'methods' => 'DELETE',
            'callback' => [$this, 'removeIPRule'],
            'permission_callback' => [$this, 'checkPermissions']
        ]);

        register_rest_route($this->namespace, '/statistics', [
            'methods' => 'GET',
            'callback' => [$this, 'getStatistics'],
            'permission_callback' => [$this, 'checkPermissions']
        ]);

        register_rest_route($this->namespace, '/threat-check', [
            'methods' => 'POST',
            'callback' => [$this, 'checkThreat'],
            'permission_callback' => [$this, 'checkPublicPermissions']
        ]);
    }

    public function getSecurityEvents(WP_REST_Request $request): WP_REST_Response
    {
        $limit = (int) $request->get_param('limit') ?: 100;
        $filters = $this->buildFilters($request);

        $events = $this->logger->getRecentEvents($limit, $filters);

        return new WP_REST_Response([
            'success' => true,
            'data' => $events,
            'total' => count($events)
        ], 200);
    }

    public function getIPRules(WP_REST_Request $request): WP_REST_Response
    {
        $ruleType = $request->get_param('type');
        $rules = $this->fetchIPRules($ruleType);

        return new WP_REST_Response([
            'success' => true,
            'data' => $rules,
            'total' => count($rules)
        ], 200);
    }

    public function addIPRule(WP_REST_Request $request): WP_REST_Response
    {
        $ipAddress = $request->get_param('ip_address');
        $ruleType = $request->get_param('rule_type');
        $reason = $request->get_param('reason');
        $duration = $request->get_param('duration') ?: 'permanent';

        if (!IPUtils::isValidIP($ipAddress)) {
            return new WP_REST_Response([
                'success' => false,
                'message' => 'Invalid IP address'
            ], 400);
        }

        $ruleData = [
            'ip_address' => $ipAddress,
            'rule_type' => $ruleType,
            'block_duration' => $duration,
            'reason' => $reason,
            'block_source' => 'api',
            'created_by' => get_current_user_id(),
            'threat_score' => 0,
            'notes' => "Added via API by " . wp_get_current_user()->user_login
        ];

        $success = $this->logger->addIPRule($ruleData);

        if ($success) {
            return new WP_REST_Response([
                'success' => true,
                'message' => 'IP rule added successfully'
            ], 201);
        } else {
            return new WP_REST_Response([
                'success' => false,
                'message' => 'Failed to add IP rule'
            ], 500);
        }
    }

    public function removeIPRule(WP_REST_Request $request): WP_REST_Response
    {
        $ipAddress = $request->get_param('ip');

        if (!IPUtils::isValidIP($ipAddress)) {
            return new WP_REST_Response([
                'success' => false,
                'message' => 'Invalid IP address'
            ], 400);
        }

        $success = $this->removeIPRuleByAddress($ipAddress);

        if ($success) {
            return new WP_REST_Response([
                'success' => true,
                'message' => 'IP rule removed successfully'
            ], 200);
        } else {
            return new WP_REST_Response([
                'success' => false,
                'message' => 'Failed to remove IP rule or rule not found'
            ], 404);
        }
    }

    public function getStatistics(WP_REST_Request $request): WP_REST_Response
    {
        $timeframe = $request->get_param('timeframe') ?: '24h';
        $stats = $this->calculateStatistics($timeframe);

        return new WP_REST_Response([
            'success' => true,
            'data' => $stats,
            'timeframe' => $timeframe
        ], 200);
    }

    public function checkThreat(WP_REST_Request $request): WP_REST_Response
    {
        $ipAddress = $request->get_param('ip_address') ?: IPUtils::getRealClientIP();

        if (!IPUtils::isValidIP($ipAddress)) {
            return new WP_REST_Response([
                'success' => false,
                'message' => 'Invalid IP address'
            ], 400);
        }

        $evaluation = $this->autoBlocker->evaluateIPThreat($ipAddress);
        $threatScore = $this->logger->getIPThreatScore($ipAddress);

        return new WP_REST_Response([
            'success' => true,
            'data' => [
                'ip_address' => $ipAddress,
                'threat_evaluation' => $evaluation,
                'threat_score' => $threatScore,
                'is_blocked' => $evaluation['action'] === 'block',
                'timestamp' => time()
            ]
        ], 200);
    }

    public function checkPermissions(): bool
    {
        return current_user_can('manage_options');
    }

    public function checkPublicPermissions(): bool
    {
        $ipAddress = IPUtils::getRealClientIP();
        $transientKey = 'ms_api_limit_' . md5($ipAddress);

        $requestCount = get_transient($transientKey);

        if ($requestCount === false) {
            set_transient($transientKey, 1, 60); // 1 request per minute
            return true;
        }

        if ($requestCount >= 10) { // Allow max 10 requests per minute
            return new \WP_Error('rest_too_many_requests', 'Too many requests.', ['status' => 429]);
        }

        set_transient($transientKey, $requestCount + 1, 60);
        return true;
    }

    private function buildFilters(WP_REST_Request $request): array
    {
        $filters = [];

        if ($request->get_param('ip_address')) {
            $filters['ip_address'] = $request->get_param('ip_address');
        }

        if ($request->get_param('event_type')) {
            $filters['event_type'] = $request->get_param('event_type');
        }

        if ($request->get_param('severity_min')) {
            $filters['severity_min'] = (int) $request->get_param('severity_min');
        }

        if ($request->get_param('since')) {
            $filters['timestamp_after'] = strtotime($request->get_param('since'));
        }

        return $filters;
    }

    private function fetchIPRules(string $ruleType = null): array
    {
        try {
            $sql = 'SELECT * FROM ms_ip_rules WHERE is_active = 1';
            $params = [];

            if ($ruleType) {
                $sql .= ' AND rule_type = ?';
                $params[] = $ruleType;
            }

            $sql .= ' ORDER BY created_at DESC';

            $stmt = $this->logger->database->prepare($sql);

            if (!$stmt) {
                return [];
            }

            foreach ($params as $index => $param) {
                $stmt->bindValue($index + 1, $param, SQLITE3_TEXT);
            }

            $result = $stmt->execute();
            $rules = [];

            while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
                $rules[] = $row;
            }

            return $rules;
        } catch (Exception $e) {
            return [];
        }
    }

    private function removeIPRuleByAddress(string $ipAddress): bool
    {
        try {
            $stmt = $this->logger->database->prepare('
                UPDATE ms_ip_rules
                SET is_active = 0,
                    updated_at = CURRENT_TIMESTAMP,
                    notes = COALESCE(notes, "") || " - Removed via API"
                WHERE ip_address = ? AND is_active = 1
            ');

            if ($stmt) {
                $stmt->bindValue(1, $ipAddress, SQLITE3_TEXT);
                $result = $stmt->execute();
                return $result !== false && $this->logger->database->changes() > 0;
            }
        } catch (Exception $e) {
            error_log("MS: Failed to remove IP rule for {$ipAddress} - " . $e->getMessage());
        }

        return false;
    }

    private function calculateStatistics(string $timeframe): array
    {
        $timeWindow = $this->getTimeWindow($timeframe);
        $events = $this->logger->getRecentEvents(10000, [
            'timestamp_after' => time() - $timeWindow
        ]);

        $stats = [
            'total_events' => count($events),
            'blocked_requests' => 0,
            'bot_detections' => 0,
            'firewall_blocks' => 0,
            'unique_ips' => 0,
            'top_countries' => [],
            'event_timeline' => []
        ];

        $eventTypes = array_count_values(array_column($events, 'event_type'));
        $uniqueIPs = array_unique(array_column($events, 'ip_address'));
        $countryCounts = [];

        $stats['blocked_requests'] = $eventTypes['request_blocked'] ?? 0;
        $stats['bot_detections'] = $eventTypes['bot_detected'] ?? 0;
        $stats['firewall_blocks'] = $eventTypes['firewall_block'] ?? 0;
        $stats['unique_ips'] = count($uniqueIPs);

        foreach ($events as $event) {
            $country = $event['country_code'] ?? 'Unknown';
            $countryCounts[$country] = ($countryCounts[$country] ?? 0) + 1;
        }

        arsort($countryCounts);
        $stats['top_countries'] = array_slice($countryCounts, 0, 10, true);
        $stats['event_timeline'] = $this->generateEventTimeline($events, $timeWindow);

        return $stats;
    }

    private function getTimeWindow(string $timeframe): int
    {
        switch ($timeframe) {
            case '1h': return 3600;
            case '6h': return 21600;
            case '12h': return 43200;
            case '24h': return 86400;
            case '7d': return 604800;
            case '30d': return 2592000;
            default: return 86400;
        }
    }

    private function generateEventTimeline(array $events, int $timeWindow): array
    {
        $buckets = 24;
        $bucketSize = $timeWindow / $buckets;
        $timeline = array_fill(0, $buckets, ['timestamp' => 0, 'count' => 0]);
        $currentTime = time();

        for ($i = 0; $i < $buckets; $i++) {
            $timeline[$i]['timestamp'] = $currentTime - ($buckets - $i) * $bucketSize;
        }

        foreach ($events as $event) {
            $bucketIndex = (int) floor(($currentTime - $event['timestamp']) / $bucketSize);
            $bucketIndex = $buckets - 1 - $bucketIndex;

            if ($bucketIndex >= 0 && $bucketIndex < $buckets) {
                $timeline[$bucketIndex]['count']++;
            }
        }

        return $timeline;
    }
}
