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
    }

    public function testSecurityPipelineBlocksMaliciousRequest(): void
    {
        $_SERVER['HTTP_USER_AGENT'] = 'sqlmap/1.0';
        $_SERVER['REQUEST_URI'] = '/wp-admin/admin-ajax.php';
        $_SERVER['REMOTE_ADDR'] = '192.168.1.100';

        ob_start();
        $this->securityCore->interceptRequest();
        $output = ob_get_clean();

        $this->assertStringContainsString('Access Denied', $output);
    }

    public function testSecurityPipelineAllowsLegitimateRequest(): void
    {
        $_SERVER['HTTP_USER_AGENT'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)';
        $_SERVER['REQUEST_URI'] = '/blog/sample-post/';
        $_SERVER['REMOTE_ADDR'] = '192.168.1.101';

        $result = $this->securityCore->interceptRequest();
        $this->assertNull($result);
    }

    public function testBotDetectionIntegration(): void
    {
        $_SERVER['HTTP_USER_AGENT'] = 'googlebot/2.1';
        $_SERVER['REMOTE_ADDR'] = '66.249.64.1';

        $result = $this->securityCore->interceptRequest();
        $this->assertNull($result);

        $events = $this->logger->getRecentEvents(10);
        $this->assertEmpty(array_filter($events, fn($e) => $e['event_type'] === 'bot_malicious'));
    }
}
