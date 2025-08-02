<?php

use PHPUnit\Framework\TestCase;
use MordenSecurity\Core\SecurityCore;
use MordenSecurity\Core\LoggerSQLite;
use MordenSecurity\Modules\IPManagement\BlockingEngine;
use MordenSecurity\Utils\IPUtils;

class SecurityCoreTest extends TestCase
{
    private $loggerMock;
    private $blockingEngineMock;
    private $securityCore;

    protected function setUp(): void
    {
        $this->loggerMock = $this->createMock(LoggerSQLite::class);
        $this->blockingEngineMock = $this->createMock(BlockingEngine::class);

        if (!function_exists('get_option')) {
            function get_option($option, $default = false) { return $default; }
        }
        if (!function_exists('is_user_logged_in')) {
            function is_user_logged_in() { return false; }
        }

        $this->securityCore = new SecurityCore();
        $reflector = new ReflectionObject($this->securityCore);

        $loggerProp = $reflector->getProperty('logger');
        $loggerProp->setAccessible(true);
        $loggerProp->setValue($this->securityCore, $this->loggerMock);

        $blockingEngineProp = $reflector->getProperty('blockingEngine');
        $blockingEngineProp->setAccessible(true);
        $blockingEngineProp->setValue($this->securityCore, $this->blockingEngineMock);
    }

    public function testInterceptRequestShouldBlockIPWhenEngineDecidesToBlock()
    {
        $testIP = '192.168.1.100';

        // Configure the mock IPUtils to return our test IP
        // This requires a bit more setup, for now we assume it works or test it manually.
        // For a real scenario, you would mock static methods if possible or refactor.

        // Configure the BlockingEngine mock
        $this->blockingEngineMock
            ->method('evaluateRequest')
            // ->with($this->equalTo($testIP)) // We can be specific about the IP
            ->willReturn(['action' => 'block', 'reason' => 'blacklisted']);

        // Expect the logger to be called to log the block event
        $this->loggerMock
            ->expects($this->once())
            ->method('logSecurityEvent');

        // Call the method under test
        $result = $this->securityCore->interceptRequest();

        // Assert that the result shows a block action
        $this->assertIsArray($result);
        $this->assertEquals('block', $result['action']);
        $this->assertEquals('blacklisted', $result['reason']);
    }
}
