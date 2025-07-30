<?php

namespace MordenSecurity\Tests\Performance;

use PHPUnit\Framework\TestCase;
use MordenSecurity\Utils\Performance;
use MordenSecurity\Core\LoggerSQLite;

class PerformanceTest extends TestCase
{
    public function testDatabaseOperationPerformance(): void
    {
        $logger = new LoggerSQLite();

        Performance::startTimer('database_test');

        for ($i = 0; $i < 100; $i++) {
            $logger->logSecurityEvent([
                'event_type' => 'test_event',
                'severity' => 1,
                'ip_address' => '192.168.1.' . ($i % 255),
                'message' => "Test event {$i}",
                'action_taken' => 'logged'
            ]);
        }

        $events = $logger->getRecentEvents(100);
        $result = Performance::endTimer('database_test');

        $this->assertLessThan(1000, $result['execution_time']);
        $this->assertCount(100, $events);
    }

    public function testSecurityOperationsBenchmark(): void
    {
        $benchmarks = Performance::benchmarkSecurityOperations();

        $this->assertArrayHasKey('ip_validation', $benchmarks);
        $this->assertArrayHasKey('threat_calculation', $benchmarks);
        $this->assertArrayHasKey('encryption', $benchmarks);

        foreach ($benchmarks as $operation => $metrics) {
            $this->assertLessThan(100, $metrics['execution_time']);
        }
    }
}
