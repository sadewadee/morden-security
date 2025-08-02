<?php

namespace MordenSecurity\Core;

if (!defined('ABSPATH')) {
    exit;
}

use SQLite3;
use SQLite3Stmt;

class LoggerSQLite
{
    public SQLite3 $database;
    private string $tableName = 'ms_security_events';
    private string $ipRulesTable = 'ms_ip_rules';
    private string $botWhitelistTable = 'ms_bot_whitelist';
    private string $dbPath;

    public function __construct()
    {
        $this->dbPath = MS_LOGS_DIR . 'security.db';
        $this->initializeDatabase();
        $this->createTables();
    }

    public function logSecurityEvent(array $eventData): bool
    {
        try {
            $stmt = $this->database->prepare('
                INSERT INTO ' . $this->tableName . '
                (event_type, severity, ip_address, user_agent, request_uri, message, context, action_taken, country_code, threat_score, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ');

            if (!$stmt) {
                return false;
            }

            $context = isset($eventData['context']) ? json_encode($eventData['context']) : '{}';
            $timestamp = time();

            $stmt->bindValue(1, $eventData['event_type'], SQLITE3_TEXT);
            $stmt->bindValue(2, $eventData['severity'] ?? 2, SQLITE3_INTEGER);
            $stmt->bindValue(3, $eventData['ip_address'] ?? '', SQLITE3_TEXT);
            $stmt->bindValue(4, $eventData['user_agent'] ?? '', SQLITE3_TEXT);
            $stmt->bindValue(5, $eventData['request_uri'] ?? '', SQLITE3_TEXT);
            $stmt->bindValue(6, $eventData['message'] ?? '', SQLITE3_TEXT);
            $stmt->bindValue(7, $context, SQLITE3_TEXT);
            $stmt->bindValue(8, $eventData['action_taken'] ?? 'logged', SQLITE3_TEXT);
            $stmt->bindValue(9, $eventData['country_code'] ?? '', SQLITE3_TEXT);
            $stmt->bindValue(10, $eventData['threat_score'] ?? 0, SQLITE3_INTEGER);
            $stmt->bindValue(11, $timestamp, SQLITE3_INTEGER);

            $result = $stmt->execute();
            $stmt->close();

            return $result !== false;
        } catch (Exception $e) {
            error_log('MS Logger Error: ' . $e->getMessage());
            return false;
        }
    }

    public function getRecentEvents(int $limit = 100, array $filters = []): array
    {
        try {
            $query = 'SELECT * FROM ' . $this->tableName . ' WHERE 1=1';
            $params = [];
            $paramIndex = 1;

            if (!empty($filters['event_type'])) {
                $query .= ' AND event_type = ?';
                $params[$paramIndex] = $filters['event_type'];
                $paramIndex++;
            }

            if (!empty($filters['ip_address'])) {
                $query .= ' AND ip_address = ?';
                $params[$paramIndex] = $filters['ip_address'];
                $paramIndex++;
            }

            if (!empty($filters['severity'])) {
                $query .= ' AND severity >= ?';
                $params[$paramIndex] = $filters['severity'];
                $paramIndex++;
            }

            if (!empty($filters['since'])) {
                $query .= ' AND timestamp >= ?';
                $params[$paramIndex] = $filters['since'];
                $paramIndex++;
            }

            $query .= ' ORDER BY timestamp DESC LIMIT ?';
            $params[$paramIndex] = $limit;

            $stmt = $this->database->prepare($query);
            if (!$stmt) {
                return [];
            }

            foreach ($params as $index => $value) {
                $stmt->bindValue($index, $value, is_int($value) ? SQLITE3_INTEGER : SQLITE3_TEXT);
            }

            $result = $stmt->execute();
            $events = [];

            while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
                $events[] = $row;
            }

            $stmt->close();
            return $events;
        } catch (Exception $e) {
            error_log('MS Logger Error: ' . $e->getMessage());
            return [];
        }
    }

    public function addIPRule(array $ruleData): bool
    {
        try {
            $stmt = $this->database->prepare('
                INSERT INTO ' . $this->ipRulesTable . '
                (ip_address, rule_type, block_duration, blocked_until, reason, threat_score, block_source, created_by, escalation_count, notes)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ');

            if (!$stmt) {
                return false;
            }

            $blockedUntil = null;
            if ($ruleData['block_duration'] !== 'permanent' && isset($ruleData['blocked_until'])) {
                $blockedUntil = $ruleData['blocked_until'];
            }

            $stmt->bindValue(1, $ruleData['ip_address'], SQLITE3_TEXT);
            $stmt->bindValue(2, $ruleData['rule_type'], SQLITE3_TEXT);
            $stmt->bindValue(3, $ruleData['block_duration'], SQLITE3_TEXT);
            $stmt->bindValue(4, $blockedUntil, SQLITE3_INTEGER);
            $stmt->bindValue(5, $ruleData['reason'] ?? '', SQLITE3_TEXT);
            $stmt->bindValue(6, $ruleData['threat_score'] ?? 0, SQLITE3_INTEGER);
            $stmt->bindValue(7, $ruleData['block_source'] ?? 'manual', SQLITE3_TEXT);
            $stmt->bindValue(8, $ruleData['created_by'] ?? null, SQLITE3_INTEGER);
            $stmt->bindValue(9, $ruleData['escalation_count'] ?? 0, SQLITE3_INTEGER);
            $stmt->bindValue(10, $ruleData['notes'] ?? '', SQLITE3_TEXT);

            $result = $stmt->execute();
            $stmt->close();

            return $result !== false;
        } catch (Exception $e) {
            error_log('MS Logger Error: ' . $e->getMessage());
            return false;
        }
    }

    public function getIPRule(string $ipAddress): ?array
    {
        try {
            $stmt = $this->database->prepare('
                SELECT * FROM ' . $this->ipRulesTable . '
                WHERE ip_address = ? AND is_active = 1
                ORDER BY created_at DESC LIMIT 1
            ');

            if (!$stmt) {
                return null;
            }

            $stmt->bindValue(1, $ipAddress, SQLITE3_TEXT);
            $result = $stmt->execute();
            $rule = $result->fetchArray(SQLITE3_ASSOC);
            $stmt->close();

            return $rule ?: null;
        } catch (Exception $e) {
            error_log('MS Logger Error: ' . $e->getMessage());
            return null;
        }
    }

    public function getIPThreatScore(string $ipAddress, int $timeWindow = 3600): int
    {
        try {
            $stmt = $this->database->prepare('
                SELECT SUM(threat_score) as total_score FROM ' . $this->tableName . '
                WHERE ip_address = ? AND timestamp >= ? AND threat_score > 0
            ');

            if (!$stmt) {
                return 0;
            }

            $stmt->bindValue(1, $ipAddress, SQLITE3_TEXT);
            $stmt->bindValue(2, time() - $timeWindow, SQLITE3_INTEGER);

            $result = $stmt->execute();
            $row = $result->fetchArray(SQLITE3_ASSOC);
            $stmt->close();

            return (int) ($row['total_score'] ?? 0);
        } catch (Exception $e) {
            error_log('MS Logger Error: ' . $e->getMessage());
            return 0;
        }
    }

    public function getSecurityStats(): array
    {
        try {
            $stats = [
                'total_events' => 0,
                'blocked_requests' => 0,
                'bot_detections' => 0,
                'firewall_blocks' => 0,
                'threat_level' => 'low'
            ];

            $stmt = $this->database->prepare('
                SELECT
                    COUNT(*) as total,
                    SUM(CASE WHEN action_taken = "blocked" THEN 1 ELSE 0 END) as blocked,
                    SUM(CASE WHEN event_type LIKE "%bot%" THEN 1 ELSE 0 END) as bots,
                    SUM(CASE WHEN event_type = "firewall_block" THEN 1 ELSE 0 END) as firewall,
                    AVG(threat_score) as avg_threat
                FROM ' . $this->tableName . '
                WHERE timestamp >= ?
            ');

            if ($stmt) {
                $stmt->bindValue(1, time() - 86400, SQLITE3_INTEGER);
                $result = $stmt->execute();
                $row = $result->fetchArray(SQLITE3_ASSOC);

                if ($row) {
                    $stats['total_events'] = (int) $row['total'];
                    $stats['blocked_requests'] = (int) $row['blocked'];
                    $stats['bot_detections'] = (int) $row['bots'];
                    $stats['firewall_blocks'] = (int) $row['firewall'];

                    $avgThreat = (float) $row['avg_threat'];
                    if ($avgThreat >= 8) {
                        $stats['threat_level'] = 'critical';
                    } elseif ($avgThreat >= 6) {
                        $stats['threat_level'] = 'high';
                    } elseif ($avgThreat >= 3) {
                        $stats['threat_level'] = 'medium';
                    }
                }

                $stmt->close();
            }

            return $stats;
        } catch (Exception $e) {
            error_log('MS Logger Error: ' . $e->getMessage());
            return [
                'total_events' => 0,
                'blocked_requests' => 0,
                'bot_detections' => 0,
                'firewall_blocks' => 0,
                'threat_level' => 'low'
            ];
        }
    }

    public function getCountryStats(int $limit = 20): array
    {
        try {
            $stmt = $this->database->prepare('
                SELECT
                    country_code,
                    COUNT(*) as total_requests,
                    SUM(CASE WHEN action_taken LIKE "%blocked%" THEN 1 ELSE 0 END) as blocked_requests,
                    SUM(threat_score) as total_threat_score
                FROM ' . $this->tableName . '
                WHERE country_code IS NOT NULL AND country_code != "" AND country_code != "None"
                GROUP BY country_code
                ORDER BY total_requests DESC
                LIMIT ?
            ');
            if (!$stmt) return [];
            $stmt->bindValue(1, $limit, SQLITE3_INTEGER);
            $result = $stmt->execute();
            $stats = [];
            while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
                $stats[$row['country_code']] = $row;
            }
            $stmt->close();
            return $stats;
        } catch (Exception $e) {
            error_log('MS Logger Error: ' . $e->getMessage());
            return [];
        }
    }

    public function cleanupOldLogs(int $daysToKeep = 30): int
    {
        try {
            $cutoffTime = time() - ($daysToKeep * 86400);

            $stmt = $this->database->prepare('
                DELETE FROM ' . $this->tableName . '
                WHERE timestamp < ?
            ');

            if ($stmt) {
                $stmt->bindValue(1, $cutoffTime, SQLITE3_INTEGER);
                $stmt->execute();
                $deletedRows = $this->database->changes();
                $stmt->close();

                return $deletedRows;
            }
        } catch (Exception $e) {
            error_log('MS Logger Error: ' . $e->getMessage());
        }

        return 0;
    }

    private function initializeDatabase(): void
    {
        if (!file_exists(dirname($this->dbPath))) {
            wp_mkdir_p(dirname($this->dbPath));
        }

        $this->database = new SQLite3($this->dbPath);
        $this->database->busyTimeout(5000);
        $this->database->exec('PRAGMA journal_mode = WAL');
        $this->database->exec('PRAGMA synchronous = NORMAL');
        $this->database->exec('PRAGMA cache_size = 10000');
        $this->database->exec('PRAGMA temp_store = memory');
    }

    public function createTables(): void
    {
        $this->createSecurityEventsTable();
        $this->createIPRulesTable();
        $this->createBotWhitelistTable();
        $this->createIndexes();
    }

    private function createSecurityEventsTable(): void
    {
        $sql = '
            CREATE TABLE IF NOT EXISTS ' . $this->tableName . ' (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                severity INTEGER NOT NULL DEFAULT 2,
                ip_address TEXT NOT NULL,
                user_agent TEXT,
                request_uri TEXT,
                message TEXT,
                context TEXT,
                action_taken TEXT,
                country_code TEXT,
                threat_score INTEGER DEFAULT 0,
                timestamp INTEGER NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ';

        $this->database->exec($sql);
    }

    private function createIPRulesTable(): void
    {
        $sql = '
            CREATE TABLE IF NOT EXISTS ' . $this->ipRulesTable . ' (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL,
                rule_type TEXT NOT NULL DEFAULT "blacklist",
                block_duration TEXT NOT NULL DEFAULT "temporary",
                blocked_until INTEGER,
                reason TEXT,
                threat_score INTEGER DEFAULT 0,
                block_source TEXT DEFAULT "manual",
                created_by INTEGER,
                escalation_count INTEGER DEFAULT 0,
                notes TEXT,
                is_active INTEGER DEFAULT 1,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ';

        $this->database->exec($sql);
    }

    private function createBotWhitelistTable(): void
    {
        $sql = '
            CREATE TABLE IF NOT EXISTS ' . $this->botWhitelistTable . ' (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_agent_pattern TEXT NOT NULL UNIQUE,
                notes TEXT,
                created_by INTEGER,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ';

        $this->database->exec($sql);
    }

    public function addBotWhitelistRule(array $ruleData): bool
    {
        try {
            $stmt = $this->database->prepare('
                INSERT INTO ' . $this->botWhitelistTable . '
                (user_agent_pattern, notes, created_by)
                VALUES (?, ?, ?)
            ');

            if (!$stmt) return false;

            $stmt->bindValue(1, $ruleData['user_agent_pattern'], SQLITE3_TEXT);
            $stmt->bindValue(2, $ruleData['notes'] ?? '', SQLITE3_TEXT);
            $stmt->bindValue(3, $ruleData['created_by'] ?? null, SQLITE3_INTEGER);

            $result = $stmt->execute();
            $stmt->close();

            return $result !== false;
        } catch (Exception $e) {
            error_log('MS Logger Error: ' . $e->getMessage());
            return false;
        }
    }

    public function getBotWhitelistRules(): array
    {
        try {
            $result = $this->database->query('SELECT * FROM ' . $this->botWhitelistTable . ' ORDER BY created_at DESC');
            $rules = [];
            while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
                $rules[] = $row;
            }
            return $rules;
        } catch (Exception $e) {
            error_log('MS Logger Error: ' . $e->getMessage());
            return [];
        }
    }

    public function removeBotWhitelistRule(int $ruleId): bool
    {
        try {
            $stmt = $this->database->prepare('DELETE FROM ' . $this->botWhitelistTable . ' WHERE id = ?');
            if (!$stmt) return false;

            $stmt->bindValue(1, $ruleId, SQLITE3_INTEGER);
            $stmt->execute();

            $changes = $this->database->changes();
            $stmt->close();

            return $changes > 0;
        } catch (Exception $e) {
            error_log('MS Logger Error: ' . $e->getMessage());
            return false;
        }
    }

    private function createIndexes(): void
    {
        $indexes = [
            'CREATE INDEX IF NOT EXISTS idx_events_ip ON ' . $this->tableName . ' (ip_address)',
            'CREATE INDEX IF NOT EXISTS idx_events_type ON ' . $this->tableName . ' (event_type)',
            'CREATE INDEX IF NOT EXISTS idx_events_timestamp ON ' . $this->tableName . ' (timestamp)',
            'CREATE INDEX IF NOT EXISTS idx_events_severity ON ' . $this->tableName . ' (severity)',
            'CREATE INDEX IF NOT EXISTS idx_rules_ip ON ' . $this->ipRulesTable . ' (ip_address)',
            'CREATE INDEX IF NOT EXISTS idx_rules_type ON ' . $this->ipRulesTable . ' (rule_type)',
            'CREATE INDEX IF NOT EXISTS idx_rules_active ON ' . $this->ipRulesTable . ' (is_active)',
            'CREATE INDEX IF NOT EXISTS idx_bot_whitelist_ua ON ' . $this->botWhitelistTable . ' (user_agent_pattern)'
        ];

        foreach ($indexes as $index) {
            $this->database->exec($index);
        }
    }

    public function __destruct()
    {
        if (isset($this->database)) {
            $this->database->close();
        }
    }
    public function getEventsByIP(string $ipAddress, int $limit = 50): array {
    try {
        $stmt = $this->database->prepare("
            SELECT * FROM ' . $this->tableName . '
            WHERE ip_address = ?
            ORDER BY timestamp DESC
            LIMIT ?
        ");

        if (!$stmt) {
            return [];
        }

        $stmt->bindValue(1, $ipAddress, SQLITE3_TEXT);
        $stmt->bindValue(2, $limit, SQLITE3_INTEGER);

        $result = $stmt->execute();
        $events = [];

        while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
            $events[] = $row;
        }

        $stmt->close();
        return $events;

    } catch (Exception $e) {
        error_log('MS Logger Error in getEventsByIP: ' . $e->getMessage());
        return [];
    }
}

    public function getBotDetectionTrends(): array
    {
        try {
            $stmt = $this->database->prepare("
                SELECT
                    strftime('%Y-%m-%d', timestamp, 'unixepoch') as date,
                    COUNT(*) as count
                FROM ' . $this->tableName . '
                WHERE event_type LIKE '%bot%'
                AND timestamp >= ?
                GROUP BY date
                ORDER BY date ASC
            ");

            if (!$stmt) return [];

            $stmt->bindValue(1, time() - (30 * 86400), SQLITE3_INTEGER);
            $result = $stmt->execute();
            $trends = [];

            while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
                $trends[$row['date']] = $row['count'];
            }

            $stmt->close();
            return $trends;
        } catch (Exception $e) {
            error_log('MS Logger Error: ' . $e->getMessage());
            return [];
        }
    }

    public function getBotTypesDistribution(): array
    {
        try {
            $stmt = $this->database->prepare("
                SELECT
                    json_extract(context, '$.type') as bot_type,
                    COUNT(*) as count
                FROM ' . $this->tableName . '
                WHERE event_type LIKE "%bot%"
                GROUP BY bot_type
            ");

            if (!$stmt) return [];

            $result = $stmt->execute();
            $types = [];

            while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
                $types[$row['bot_type']] = $row['count'];
            }

            $stmt->close();
            return $types;
        } catch (Exception $e) {
            error_log('MS Logger Error: ' . $e->getMessage());
            return [];
        }
    }

    public function getBotDetectionStats(): array
    {
        $trends = [];
        $types = [];

        // Get bot detection trends for the last 24 hours, grouped by hour
        $twentyFourHoursAgo = time() - (24 * 3600);
        $query = "SELECT
                        strftime('%H', timestamp, 'unixepoch') as hour,
                        COUNT(*) as count
                    FROM " . $this->tableName . "
                    WHERE event_type LIKE '%bot%' AND timestamp >= :start_time
                    GROUP BY hour
                    ORDER BY hour ASC";

        $stmt = $this->database->prepare($query);
        $stmt->bindValue(':start_time', $twentyFourHoursAgo, SQLITE3_INTEGER);
        $result = $stmt->execute();

        while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
            $trends[$row['hour']] = $row['count'];
        }
        $stmt->close();

        // Ensure all 24 hours are present, even if no data
        for ($i = 0; $i < 24; $i++) {
            $hour = str_pad($i, 2, '0', STR_PAD_LEFT);
            if (!isset($trends[$hour])) {
                $trends[$hour] = 0;
            }
        }
        ksort($trends);

        // Get bot types distribution
        $query = "SELECT
                        json_extract(context, '$.type') as bot_type,
                        COUNT(*) as count
                    FROM " . $this->tableName . "
                    WHERE event_type LIKE '%bot%'
                    GROUP BY bot_type
                    ORDER BY count DESC";

        $result = $this->database->query($query);
        while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
            $type = $row['bot_type'] ?? 'unknown';
            $types[$type] = $row['count'];
        }

        return [
            'trends' => $trends,
            'types' => $types
        ];
    }
}
