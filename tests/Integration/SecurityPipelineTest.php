<?php

namespace MordenSecurity\Tests\Integration;

use PHPUnit\Framework\TestCase;
use MordenSecurity\Core\SecurityCore;
use MordenSecurity\Core\LoggerSQLite;

class SecurityPipelineTest extends TestCase
{
    private SecurityCore $securityCore;
    private LoggerSQLite $logger;

    protected function setUp(): void
    {
        $this->logger = new LoggerSQLite();
        $this->securityCore = new SecurityCore();

        // Enable security for testing
        update_option('ms_security_enabled', true);
        update_option('ms_bot_detection_enabled', true);
    }

    public function testSecurityPipelineBlocksMaliciousRequest(): void
    {
        $_SERVER['HTTP_USER_AGENT'] = 'sqlmap/1.0';
        $_SERVER['REQUEST_URI'] = '/wp-admin/admin-ajax.php';
        $_SERVER['REMOTE_ADDR'] = '192.168.1.100';
        $_SERVER['REQUEST_METHOD'] = 'GET';

        $this->expectOutputRegex('/Access Denied/');

        try {
            $this->securityCore->interceptRequest();
        } catch (Exception $e) {
            // Expected to exit, ignore the exception
        }
    }

    public function testSecurityPipelineAllowsLegitimateRequest(): void
    {
        $_SERVER['HTTP_USER_AGENT'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36';
        $_SERVER['REQUEST_URI'] = '/blog/sample-post/';
        $_SERVER['REMOTE_ADDR'] = '192.168.1.101';
        $_SERVER['REQUEST_METHOD'] = 'GET';

        $result = $this->securityCore->interceptRequest();
        $this->assertNull($result);
    }

    public function testBotDetectionIntegration(): void
    {
        $_SERVER['HTTP_USER_AGENT'] = 'googlebot/2.1';
        $_SERVER['REMOTE_ADDR'] = '66.249.64.1';
        $_SERVER['REQUEST_METHOD'] = 'GET';

        $result = $this->securityCore->interceptRequest();
        $this->assertNull($result);

        $events = $this->logger->getRecentEvents(10);
        $maliciousBotEvents = array_filter($events, fn($e) => $e['event_type'] === 'malicious_bot_blocked');
        $this->assertEmpty($maliciousBotEvents);
    }

    protected function tearDown(): void
    {
        // Clean up server variables
        unset($_SERVER['HTTP_USER_AGENT']);
        unset($_SERVER['REQUEST_URI']);
        unset($_SERVER['REMOTE_ADDR']);
        unset($_SERVER['REQUEST_METHOD']);
    }
}
