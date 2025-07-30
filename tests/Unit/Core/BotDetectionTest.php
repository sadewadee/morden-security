<?php

namespace MordenSecurity\Tests\Unit\Core;

use PHPUnit\Framework\TestCase;
use MordenSecurity\Core\LoggerSQLite;
use MordenSecurity\Core\BotDetection;

class BotDetectionTest extends TestCase
{
    private $logger;
    private $botDetection;

    protected function setUp(): void
    {
        $this->logger = $this->createMock(LoggerSQLite::class);
        $this->botDetection = new BotDetection($this->logger);
    }

    public function testAnalyzeRequestReturnsArray()
    {
        $this->logger->method('logSecurityEvent')->willReturn(true);

        $result = $this->botDetection->analyzeRequest();

        $this->assertIsArray($result);
        $this->assertArrayHasKey('is_bot', $result);
        $this->assertArrayHasKey('confidence', $result);
        $this->assertArrayHasKey('type', $result);
        $this->assertArrayHasKey('action', $result);
    }

    public function testIsMaliciousBotDetectsBot()
    {
        $this->logger->method('logSecurityEvent')->willReturn(true);

        $this->assertTrue($this->botDetection->isMaliciousBot('sqlmap', '1.2.3.4'));
        $this->assertTrue($this->botDetection->isMaliciousBot('curl/7.54.0', '5.6.7.8'));
    }

    public function testIsGoodBotDetectsGoodBots()
    {
        $this->logger->method('logSecurityEvent')->willReturn(true);

        $this->assertTrue($this->botDetection->isGoodBot('googlebot'));
        $this->assertTrue($this->botDetection->isGoodBot('bingbot/2.0'));
    }
}
