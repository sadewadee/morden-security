<?php

namespace MordenSecurity\Tests\Unit\Core;

use PHPUnit\Framework\TestCase;
use MordenSecurity\Core\LoggerSQLite;
use MordenSecurity\Core\AutoIPBlocker;

class AutoIPBlockerTest extends TestCase
{
    private $logger;
    private $autoBlocker;

    protected function setUp(): void
    {
        $this->logger = $this->createMock(LoggerSQLite::class);
        $this->autoBlocker = new AutoIPBlocker($this->logger);
    }

    public function testEvaluateIPThreatReturnsArray(): void
    {
        $this->logger->method('getIPRule')->willReturn(null);
        $this->logger->method('getIPThreatScore')->willReturn(25);
        $this->logger->method('logSecurityEvent')->willReturn(true);

        $result = $this->autoBlocker->evaluateIPThreat('192.168.1.1');

        $this->assertIsArray($result);
        $this->assertArrayHasKey('action', $result);
        $this->assertArrayHasKey('reason', $result);
    }

    public function testBlockIPReturnsTrueOnSuccess(): void
    {
        $this->logger->method('addIPRule')->willReturn(true);
        $this->logger->method('getIPThreatScore')->willReturn(100);
        $this->logger->method('logSecurityEvent')->willReturn(true);

        $result = $this->autoBlocker->blockIP('192.168.1.1', 'test_reason');

        $this->assertTrue($result);
    }

    public function testPrivateIPsAreAllowed(): void
    {
        $this->logger->method('getIPRule')->willReturn(null);
        $this->logger->method('logSecurityEvent')->willReturn(true);

        $result = $this->autoBlocker->evaluateIPThreat('192.168.1.1');

        $this->assertEquals('allow', $result['action']);
        $this->assertEquals('private_ip', $result['reason']);
    }
}
