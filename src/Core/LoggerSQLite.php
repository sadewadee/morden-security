<?php

namespace MordenSecurity\Core;

if (!defined('ABSPATH')) {
    exit;
}

class LoggerSQLite
{
    private ?SQLite3 $database = null;
    private string $databasePath;
    private bool $isInitialized = false;

    public function __construct()
    {
        $this->databasePath = MS_LOGS_DIR . 'security.db';
        $this->initializeDatabase();
    }

    public function logSecurityEvent(array $eventData): bool
    {
        if (!$this->isInitialized) {
            return false;
        }

        $stmt = $this->database->prepare('
            INSERT INTO ms_security_events
            (timestamp, event_type, severity, ip_address, user_id, user_agent,
             request_uri, message, context, action_taken, country_code, threat_score, blocked_reason)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ');

        if (!$stmt) {
            return false;
        }

        $stmt->bindValue(1, $eventData['timestamp'] ?? time(), SQLITE3_INTEGER);
        $stmt->bindValue(2, $eventData['event_type'] ?? 'unknown', SQLITE3_TEXT);
        $stmt->bindValue(3, $eventData['severity'] ?? 1, SQLITE3_INTEGER);
        $stmt->bindValue(4, $eventData['ip_address'] ?? '', SQLITE3_TEXT);
        $stmt->bindValue(5, $eventData['user_id'] ?? null, SQLITE3_INTEGER);
        $stmt->bindValue(6, $eventData['user_agent'] ?? '', SQLITE3_TEXT);
        $stmt->bindValue(7, $eventData['request_uri'] ?? '', SQLITE3_TEXT);
        $stmt->bindValue(8, $eventData['message'] ?? '', SQLITE3_TEXT);
        $stmt->bindValue(9, json_encode($eventData['context'] ?? []), SQLITE3_TEXT);
        $stmt->bindValue(10, $eventData['action_taken'] ?? 'none', SQLITE3_TEXT);
        $stmt->bindValue(11, $eventData['country_code'] ?? 'None', SQLITE3_TEXT);
        $stmt->bindValue(12, $eventData['threat_score'] ?? 0, SQLITE3_INTEGER);
        $stmt->bindValue(13, $eventData['blocked_reason'] ?? null, SQLITE3_TEXT);

        $result = $stmt->execute();
        return $result !== false;
    }

    public function getRecentEvents(int $limit = 100, array $filters = []): array
    {
        if (!$this->isInitialized) {
            return [];
        }

        $whereClause = $this->buildWhereClause($filters);
        $sql = "SELECT * FROM ms_security_events {$whereClause} ORDER BY timestamp DESC LIMIT ?";

        $stmt = $this->database->prepare($sql);
        if (!$stmt) {
            return [];
        }

        $paramIndex = 1;
        $this->bindFilterValues($stmt, $filters, $paramIndex);
        $stmt->bindValue($paramIndex, $limit, SQLITE3_INTEGER);

        $result = $stmt->execute();
        $events = [];

        while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
            $row['context'] = json_decode($row['context'], true) ?? [];
            $events[] = $row;
        }

        return $events;
    }

    public function getIPThreatScore(string $ipAddress, int $timeWindow = 3600): int
    {
        if (!$this->isInitialized) {
            return 0;
        }

        $stmt = $this->database->prepare('
            SELECT SUM(
                CASE
                    WHEN severity = 4 THEN 30
                    WHEN severity = 3 THEN 20
                    WHEN severity = 2 THEN 10
                    ELSE 5
                END
            ) as total_threat_score
            FROM ms_security_events
            WHERE ip_address = ?
              AND timestamp > ?
              AND event_type IN ("firewall_block", "heuristic_detect", "bot_malicious")
        ');

        if (!$stmt) {
            return 0;
        }

        $stmt->bindValue(1, $ipAddress, SQLITE3_TEXT);
        $stmt->bindValue(2, time() - $timeWindow, SQLITE3_INTEGER);

        $result = $stmt->execute();
        $row = $result->fetchArray(SQLITE3_ASSOC);

        return (int) ($row['total_threat_score'] ?? 0);
    }

    public function addIPRule(array $ruleData): bool
    {
        if (!$this->isInitialized) {
            return false;
        }

        $stmt = $this->database->prepare('
            INSERT OR REPLACE INTO ms_ip_rules
            (ip_address, rule_type, block_duration, blocked_until, reason, threat_score,
             block_source, created_by, expires_at, notes, escalation_count)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ');

        if (!$stmt) {
            return false;
        }

        $stmt->bindValue(1, $ruleData['ip_address'], SQLITE3_TEXT);
        $stmt->bindValue(2, $ruleData['rule_type'], SQLITE3_TEXT);
        $stmt->bindValue(3, $ruleData['block_duration'], SQLITE3_TEXT);
        $stmt->bindValue(4, $ruleData['blocked_until'] ?? null, SQLITE3_INTEGER);
        $stmt->bindValue(5, $ruleData['reason'] ?? null, SQLITE3_TEXT);
        $stmt->bindValue(6, $ruleData['threat_score'] ?? 0, SQLITE3_INTEGER);
        $stmt->bindValue(7, $ruleData['block_source'], SQLITE3_TEXT);
        $stmt->bindValue(8, $ruleData['created_by'] ?? null, SQLITE3_INTEGER);
        $stmt->bindValue(9, $ruleData['expires_at'] ?? null, SQLITE3_INTEGER);
        $stmt->bindValue(10, $ruleData['notes'] ?? null, SQLITE3_TEXT);
        $stmt->bindValue(11, $ruleData['escalation_count'] ?? 0, SQLITE3_INTEGER);

        $result = $stmt->execute();
        return $result !== false;
    }

    public function getIPRule(string $ipAddress): ?array
    {
        if (!$this->isInitialized) {
            return null;
        }

        $stmt = $this->database->prepare('
            SELECT * FROM ms_ip_rules
            WHERE ip_address = ? AND is_active = 1
            ORDER BY
                CASE rule_type
                    WHEN "whitelist" THEN 1
                    WHEN "blacklist" THEN 2
                    WHEN "auto_blocked" THEN 3
                    ELSE 4
                END
            LIMIT 1
        ');

        if (!$stmt) {
            return null;
        }

        $stmt->bindValue(1, $ipAddress, SQLITE3_TEXT);
        $result = $stmt->execute();
        $row = $result->fetchArray(SQLITE3_ASSOC);

        return $row ?: null;
    }

    public function createTables(): bool
    {
        if (!$this->database) {
            return false;
        }

        $tables = [
            'ms_security_events' => '
                CREATE TABLE IF NOT EXISTS ms_security_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp INTEGER NOT NULL,
                    event_type TEXT NOT NULL,
                    severity INTEGER NOT NULL DEFAULT 1,
                    ip_address TEXT NOT NULL,
                    user_id INTEGER DEFAULT NULL,
                    user_agent TEXT DEFAULT NULL,
                    request_uri TEXT DEFAULT NULL,
                    message TEXT NOT NULL,
                    context TEXT DEFAULT NULL,
                    action_taken TEXT DEFAULT NULL,
                    country_code TEXT DEFAULT "None",
                    threat_score INTEGER DEFAULT 0,
                    blocked_reason TEXT DEFAULT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                );
                CREATE INDEX IF NOT EXISTS idx_events_timestamp ON ms_security_events(timestamp);
                CREATE INDEX IF NOT EXISTS idx_events_ip ON ms_security_events(ip_address);
                CREATE INDEX IF NOT EXISTS idx_events_type ON ms_security_events(event_type);
            ',
            'ms_ip_rules' => '
                CREATE TABLE IF NOT EXISTS ms_ip_rules (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT NOT NULL UNIQUE,
                    rule_type TEXT NOT NULL CHECK(rule_type IN ("whitelist", "blacklist", "auto_blocked")),
                    block_duration TEXT NOT NULL CHECK(block_duration IN ("temporary", "permanent")),
                    blocked_until INTEGER DEFAULT NULL,
                    reason TEXT DEFAULT NULL,
                    threat_score INTEGER DEFAULT 0,
                    block_source TEXT NOT NULL CHECK(block_source IN ("manual", "auto_threat", "auto_bot")),
                    created_by INTEGER DEFAULT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    expires_at DATETIME DEFAULT NULL,
                    notes TEXT DEFAULT NULL,
                    is_active INTEGER DEFAULT 1,
                    escalation_count INTEGER DEFAULT 0,
                    last_activity INTEGER DEFAULT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_ip_address ON ms_ip_rules(ip_address);
                CREATE INDEX IF NOT EXISTS idx_rule_type ON ms_ip_rules(rule_type);
                CREATE INDEX IF NOT EXISTS idx_is_active ON ms_ip_rules(is_active);
            '
        ];

        foreach ($tables as $tableName => $sql) {
            if (!$this->database->exec($sql)) {
                return false;
            }
        }

        return true;
    }

    private function initializeDatabase(): void
    {
        if (!file_exists(MS_LOGS_DIR)) {
            wp_mkdir_p(MS_LOGS_DIR);
        }

        try {
            $this->database = new SQLite3($this->databasePath);
            $this->database->exec('PRAGMA journal_mode = WAL');
            $this->database->exec('PRAGMA synchronous = NORMAL');
            $this->database->exec('PRAGMA cache_size = 10000');
            $this->database->exec('PRAGMA temp_store = MEMORY');

            $this->createTables();
            $this->isInitialized = true;
        } catch (Exception $e) {
            $this->isInitialized = false;
        }
    }

    private function buildWhereClause(array $filters): string
    {
        if (empty($filters)) {
            return '';
        }

        $conditions = [];

        if (isset($filters['ip_address'])) {
            $conditions[] = 'ip_address = ?';
        }

        if (isset($filters['event_type'])) {
            $conditions[] = 'event_type = ?';
        }

        if (isset($filters['severity_min'])) {
            $conditions[] = 'severity >= ?';
        }

        if (isset($filters['timestamp_after'])) {
            $conditions[] = 'timestamp > ?';
        }

        return empty($conditions) ? '' : 'WHERE ' . implode(' AND ', $conditions);
    }

    private function bindFilterValues(SQLite3Stmt $stmt, array $filters, int &$paramIndex): void
    {
        if (isset($filters['ip_address'])) {
            $stmt->bindValue($paramIndex++, $filters['ip_address'], SQLITE3_TEXT);
        }

        if (isset($filters['event_type'])) {
            $stmt->bindValue($paramIndex++, $filters['event_type'], SQLITE3_TEXT);
        }

        if (isset($filters['severity_min'])) {
            $stmt->bindValue($paramIndex++, $filters['severity_min'], SQLITE3_INTEGER);
        }

        if (isset($filters['timestamp_after'])) {
            $stmt->bindValue($paramIndex++, $filters['timestamp_after'], SQLITE3_INTEGER);
        }
    }

    public function __destruct()
    {
        if ($this->database) {
            $this->database->close();
        }
    }
}
