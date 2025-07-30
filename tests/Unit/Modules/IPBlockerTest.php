<?php

namespace MordenSecurity\Tests\Unit\Modules;

use PHPUnit\Framework\TestCase;
use MordenSecurity\Core\LoggerSQLite;
use MordenSecurity\Modules\IPManagement\IPBlocker;
use SQLite3;

class IPBlockerTest extends TestCase
{
    private $logger;
    private $ipBlocker;

    protected function setUp(): void
    {
        $this->logger = $this->createMock(LoggerSQLite::class);
        $this->logger->database = $this->createMock(SQLite3::class);
        $this->ipBlocker = new IPBlocker($this->logger);
    }

    public function testIsBlockedReturnsFalseForNonBlockedIP(): void
    {
        $this->logger->method('getIPRule')->willReturn(null);

        $result = $this->ipBlocker->isBlocked('192.168.1.1');

        $this->assertFalse($result['blocked']);
        $this->assertEquals('not_blocked', $result['reason']);
    }

    public function testIsBlockedReturnsTrueForBlockedIP(): void
    {
        $mockRule = [
            'id' => 1,
            'ip_address' => '192.168.1.100',
            'rule_type' => 'blacklist',
            'block_duration' => 'temporary',
            'is_active' => 1,
            'blocked_until' => time() + 3600,
            'reason' => 'Test block'
        ];

        $this->logger->method('getIPRule')->willReturn($mockRule);

        $result = $this->ipBlocker->isBlocked('192.168.1.100');

        $this->assertTrue($result['blocked']);
        $this->assertEquals('Test block', $result['reason']);
        $this->assertEquals('blacklist', $result['block_type']);
    }

    public function testIsBlockedReturnsFalseForExpiredBlock(): void
    {
        $mockRule = [
            'id' => 1,
            'ip_address' => '192.168.1.100',
            'rule_type' => 'blacklist',
            'block_duration' => 'temporary',
            'is_active' => 1,
            'blocked_until' => time() - 3600,
            'reason' => 'Expired block'
        ];

        $this->logger->method('getIPRule')->willReturn($mockRule);

        $result = $this->ipBlocker->isBlocked('192.168.1.100');

        $this->assertFalse($result['blocked']);
        $this->assertEquals('expired', $result['reason']);
    }

    public function testIsBlockedReturnsFalseForWhitelistedIP(): void
    {
        $mockRule = [
            'id' => 1,
            'ip_address' => '192.168.1.50',
            'rule_type' => 'whitelist',
            'block_duration' => 'permanent',
            'is_active' => 1,
            'blocked_until' => null,
            'reason' => 'Whitelisted'
        ];

        $this->logger->method('getIPRule')->willReturn($mockRule);

        $result = $this->ipBlocker->isBlocked('192.168.1.50');

        $this->assertFalse($result['blocked']);
        $this->assertEquals('whitelisted', $result['reason']);
        $this->assertArrayHasKey('rule', $result);
    }

    public function testAddBlockReturnsFalseForInvalidIP(): void
    {
        $result = $this->ipBlocker->addBlock('invalid-ip', []);

        $this->assertFalse($result);
    }

    public function testAddBlockReturnsTrueForValidIP(): void
    {
        $this->logger->method('addIPRule')->willReturn(true);
        $this->logger->method('getIPRule')->willReturn(null);
        $this->logger->method('logSecurityEvent')->willReturn(true);

        $blockData = [
            'reason' => 'Test block',
            'duration' => 'temporary',
            'threat_score' => 50
        ];

        $result = $this->ipBlocker->addBlock('192.168.1.200', $blockData);

        $this->assertTrue($result);
    }

    public function testRemoveBlockReturnsFalseForInvalidIP(): void
    {
        $result = $this->ipBlocker->removeBlock('invalid-ip');

        $this->assertFalse($result);
    }

    public function testAddWhitelistReturnsTrueForValidIP(): void
    {
        $this->logger->method('addIPRule')->willReturn(true);
        $this->logger->method('logSecurityEvent')->willReturn(true);

        $whitelistData = [
            'reason' => 'Trusted IP',
            'notes' => 'Admin whitelist'
        ];

        $result = $this->ipBlocker->addWhitelist('192.168.1.10', $whitelistData);

        $this->assertTrue($result);
    }

    public function testGetBlockStatisticsReturnsArray(): void
    {
        $stats = $this->ipBlocker->getBlockStatistics();

        $this->assertIsArray($stats);
        $this->assertArrayHasKey('total_blocked', $stats);
        $this->assertArrayHasKey('temporary_blocks', $stats);
        $this->assertArrayHasKey('permanent_blocks', $stats);
        $this->assertArrayHasKey('whitelisted', $stats);
    }
}
