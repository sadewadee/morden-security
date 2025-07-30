<?php

namespace MordenSecurity\Utils;

if (!defined('ABSPATH')) {
    exit;
}

class Performance
{
    private static array $timers = [];
    private static array $memoryUsage = [];

    public static function startTimer(string $name): void
    {
        self::$timers[$name] = [
            'start' => microtime(true),
            'memory_start' => memory_get_usage(true)
        ];
    }

    public static function endTimer(string $name): array
    {
        if (!isset(self::$timers[$name])) {
            return ['error' => 'Timer not found'];
        }

        $timer = self::$timers[$name];
        $endTime = microtime(true);
        $endMemory = memory_get_usage(true);

        $result = [
            'execution_time' => round(($endTime - $timer['start']) * 1000, 2),
            'memory_used' => $endMemory - $timer['memory_start'],
            'memory_formatted' => self::formatBytes($endMemory - $timer['memory_start'])
        ];

        unset(self::$timers[$name]);

        return $result;
    }

    public static function measureFunction(callable $function, ...$args): array
    {
        $startTime = microtime(true);
        $startMemory = memory_get_usage(true);

        $result = call_user_func_array($function, $args);

        $endTime = microtime(true);
        $endMemory = memory_get_usage(true);

        return [
            'result' => $result,
            'execution_time' => round(($endTime - $startTime) * 1000, 2),
            'memory_used' => $endMemory - $startMemory,
            'memory_formatted' => self::formatBytes($endMemory - $startMemory)
        ];
    }

    public static function checkDatabasePerformance(LoggerSQLite $logger): array
    {
        $tests = [
            'simple_select' => function() use ($logger) {
                return $logger->getRecentEvents(10);
            },
            'complex_query' => function() use ($logger) {
                return $logger->getRecentEvents(100, ['event_type' => 'request_blocked']);
            },
            'ip_lookup' => function() use ($logger) {
                return $logger->getIPRule('192.168.1.1');
            },
            'threat_calculation' => function() use ($logger) {
                return $logger->getIPThreatScore('192.168.1.1');
            }
        ];

        $results = [];

        foreach ($tests as $testName => $testFunction) {
            $results[$testName] = self::measureFunction($testFunction);
        }

        return [
            'tests' => $results,
            'overall_health' => self::calculateDatabaseHealth($results)
        ];
    }

    public static function optimizeDatabase(LoggerSQLite $logger): array
    {
        $optimizations = [];

        try {
            $logger->database->exec('VACUUM');
            $optimizations[] = 'Database vacuumed';

            $logger->database->exec('REINDEX');
            $optimizations[] = 'Indexes rebuilt';

            $logger->database->exec('ANALYZE');
            $optimizations[] = 'Statistics updated';

        } catch (Exception $e) {
            $optimizations[] = 'Optimization failed: ' . $e->getMessage();
        }

        return $optimizations;
    }

    public static function getSystemResources(): array
    {
        return [
            'memory_limit' => ini_get('memory_limit'),
            'memory_usage' => self::formatBytes(memory_get_usage(true)),
            'memory_peak' => self::formatBytes(memory_get_peak_usage(true)),
            'execution_time_limit' => ini_get('max_execution_time'),
            'php_version' => PHP_VERSION,
            'extensions' => [
                'sqlite3' => extension_loaded('sqlite3'),
                'openssl' => extension_loaded('openssl'),
                'json' => extension_loaded('json')
            ]
        ];
    }

    public static function benchmarkSecurityOperations(): array
    {
        $operations = [];

        $operations['ip_validation'] = self::measureFunction(function() {
            $testIPs = ['192.168.1.1', '10.0.0.1', '172.16.0.1', '8.8.8.8'];
            foreach ($testIPs as $ip) {
                IPUtils::isValidIP($ip);
            }
        });

        $operations['threat_calculation'] = self::measureFunction(function() {
            for ($i = 0; $i < 100; $i++) {
                $score = rand(0, 1000);
                Validation::validateThreatScore($score);
            }
        });

        $operations['encryption'] = self::measureFunction(function() {
            $testData = str_repeat('test data ', 100);
            $encrypted = Encryption::encrypt($testData);
            Encryption::decrypt($encrypted);
        });

        return $operations;
    }

    public static function cleanupOldData(LoggerSQLite $logger, int $daysToKeep = 30): array
    {
        $cutoffTime = time() - ($daysToKeep * 86400);
        $cleanupResults = [];

        try {
            $stmt = $logger->database->prepare('
                DELETE FROM ms_security_events
                WHERE timestamp < ?
                  AND event_type NOT IN ("ip_auto_blocked", "firewall_block")
            ');

            if ($stmt) {
                $stmt->bindValue(1, $cutoffTime, SQLITE3_INTEGER);
                $result = $stmt->execute();

                if ($result) {
                    $deletedCount = $logger->database->changes();
                    $cleanupResults['events_cleaned'] = $deletedCount;
                }
            }

            $stmt = $logger->database->prepare('
                UPDATE ms_ip_rules
                SET is_active = 0
                WHERE blocked_until IS NOT NULL
                  AND blocked_until < ?
            ');

            if ($stmt) {
                $stmt->bindValue(1, time(), SQLITE3_INTEGER);
                $result = $stmt->execute();

                if ($result) {
                    $expiredCount = $logger->database->changes();
                    $cleanupResults['expired_blocks'] = $expiredCount;
                }
            }

        } catch (Exception $e) {
            $cleanupResults['error'] = $e->getMessage();
        }

        return $cleanupResults;
    }

    private static function formatBytes(int $bytes): string
    {
        $units = ['B', 'KB', 'MB', 'GB', 'TB'];

        for ($i = 0; $bytes > 1024 && $i < count($units) - 1; $i++) {
            $bytes /= 1024;
        }

        return round($bytes, 2) . ' ' . $units[$i];
    }

    private static function calculateDatabaseHealth(array $results): string
    {
        $totalTime = 0;
        $testCount = 0;

        foreach ($results as $test) {
            $totalTime += $test['execution_time'];
            $testCount++;
        }

        $avgTime = $testCount > 0 ? $totalTime / $testCount : 0;

        if ($avgTime < 10) return 'excellent';
        if ($avgTime < 50) return 'good';
        if ($avgTime < 100) return 'fair';
        return 'poor';
    }
}
