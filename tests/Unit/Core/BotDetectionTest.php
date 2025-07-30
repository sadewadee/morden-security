<?php

namespace MordenSecurity\Tests\Unit\Core;

use PHPUnit\Framework\TestCase;
use MordenSecurity\Core\LoggerSQLite;
use MordenSecurity\Core\BotDetection;

class BotDetectionTest extends TestCase
{
    public function testAnalyzeRequestReturnsArray()
    {
        $logger = $this->createMock(LoggerSQLite::class);
        $botDetection = new BotDetection($logger);

        $result = $botDetection->analyzeRequest();

        $this->assertIsArray($result);
        $this->assertArrayHasKey('is_bot', $result);
        $this->assertArrayHasKey('confidence', $result);
        $this->assertArrayHasKey('type', $result);
        $this->assertArrayHasKey('action', $result);
    }

    public function testIsMaliciousBotDetectsBot()
    {
        $logger = $this->createMock(LoggerSQLite::class);
        $botDetection = new BotDetection($logger);

        $this->assertTrue($botDetection->isMaliciousBot('sqlmap', '1.2.3.4'));
        $this->assertTrue($botDetection->isMaliciousBot('curl/7.54.0', '5.6.7.8'));
    }

    public function testIsGoodBotDetectsGoodBots()
    {
        $logger = $this->createMock(LoggerSQLite::class);
        $botDetection = new BotDetection($logger);

        $this->assertTrue($botDetection->isGoodBot('googlebot'));
        $this->assertTrue($botDetection->isGoodBot('bingbot/2.0'));
    }
}
