<?php

namespace MordenSecurity\API\Endpoints;

use MordenSecurity\Core\LoggerSQLite;
use MordenSecurity\Utils\IPUtils;
use MordenSecurity\Utils\Validation;

if (!defined('ABSPATH')) {
    exit;
}

class IPManagementEndpoint
{
    private LoggerSQLite $logger;

    public function __construct(LoggerSQLite $logger)
    {
        $this->logger = $logger;
    }

    public function getBlockedIPs(WP_REST_Request $request): WP_REST_Response
    {
        $page = max(1, (int) $request->get_param('page'));
        $perPage = min(100, max(10, (int) $request->get_param('per_page')));
        $offset = ($page - 1) * $perPage;

        try {
            $stmt = $this->logger->database->prepare('
                SELECT * FROM ms_ip_rules
                WHERE rule_type IN ("blacklist", "auto_blocked")
                  AND is_active = 1
                ORDER BY created_at DESC
                LIMIT ? OFFSET ?
            ');

            $stmt->bindValue(1, $perPage, SQLITE3_INTEGER);
            $stmt->bindValue(2, $offset, SQLITE3_INTEGER);

            $result = $stmt->execute();
            $rules = [];

            while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
                $rules[] = $this->formatIPRule($row);
            }

            return new WP_REST_Response([
                'success' => true,
                'data' => $rules,
                'pagination' => [
                    'page' => $page,
                    'per_page' => $perPage,
                    'total' => $this->getTotalBlockedIPs()
                ]
            ], 200);

        } catch (Exception $e) {
            return new WP_REST_Response([
                'success' => false,
                'message' => 'Database error occurred'
            ], 500);
        }
    }

    public function addIPRule(WP_REST_Request $request): WP_REST_Response
    {
        $ipAddress = Validation::sanitizeIPAddress($request->get_param('ip_address'));
        $ruleType = Validation::validateRuleType($request->get_param('rule_type'));
        $duration = Validation::validateBlockDuration($request->get_param('duration'));
        $reason = sanitize_text_field($request->get_param('reason'));

        if (empty($ipAddress) || !IPUtils::isValidIP($ipAddress)) {
            return new WP_REST_Response([
                'success' => false,
                'message' => 'Invalid IP address format'
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
            'notes' => 'Added via REST API'
        ];

        $success = $this->logger->addIPRule($ruleData);

        if ($success) {
            return new WP_REST_Response([
                'success' => true,
                'message' => 'IP rule added successfully',
                'data' => $ruleData
            ], 201);
        }

        return new WP_REST_Response([
            'success' => false,
            'message' => 'Failed to add IP rule'
        ], 500);
    }

    public function removeIPRule(WP_REST_Request $request): WP_REST_Response
    {
        $ipAddress = Validation::sanitizeIPAddress($request->get_param('ip'));

        if (empty($ipAddress) || !IPUtils::isValidIP($ipAddress)) {
            return new WP_REST_Response([
                'success' => false,
                'message' => 'Invalid IP address format'
            ], 400);
        }

        try {
            $stmt = $this->logger->database->prepare('
                UPDATE ms_ip_rules
                SET is_active = 0, updated_at = CURRENT_TIMESTAMP
                WHERE ip_address = ? AND is_active = 1
            ');

            $stmt->bindValue(1, $ipAddress, SQLITE3_TEXT);
            $result = $stmt->execute();

            if ($result && $this->logger->database->changes() > 0) {
                return new WP_REST_Response([
                    'success' => true,
                    'message' => 'IP rule removed successfully'
                ], 200);
            }

            return new WP_REST_Response([
                'success' => false,
                'message' => 'IP rule not found or already inactive'
            ], 404);

        } catch (Exception $e) {
            return new WP_REST_Response([
                'success' => false,
                'message' => 'Database error occurred'
            ], 500);
        }
    }

    private function formatIPRule(array $row): array
    {
        $geoData = IPUtils::getIPGeolocation($row['ip_address']);

        return [
            'id' => $row['id'],
            'ip_address' => $row['ip_address'],
            'rule_type' => $row['rule_type'],
            'block_duration' => $row['block_duration'],
            'reason' => $row['reason'],
            'threat_score' => (int) $row['threat_score'],
            'created_at' => $row['created_at'],
            'expires_at' => $row['expires_at'],
            'country' => $geoData['country_code'],
            'is_expired' => $row['blocked_until'] && $row['blocked_until'] < time()
        ];
    }

    private function getTotalBlockedIPs(): int
    {
        try {
            $result = $this->logger->database->query('
                SELECT COUNT(*) as total FROM ms_ip_rules
                WHERE rule_type IN ("blacklist", "auto_blocked") AND is_active = 1
            ');

            $row = $result->fetchArray(SQLITE3_ASSOC);
            return (int) $row['total'];
        } catch (Exception $e) {
            return 0;
        }
    }
}
