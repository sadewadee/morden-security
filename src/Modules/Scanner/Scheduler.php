<?php

namespace MordenSecurity\Modules\Scanner;

if (!defined('ABSPATH')) {
    exit;
}

class Scheduler
{
    public const CRON_HOOK = 'ms_run_scheduled_scan';

    public static function schedule(string $frequency): void
    {
        if (!wp_next_scheduled(self::CRON_HOOK)) {
            wp_schedule_event(time(), $frequency, self::CRON_HOOK);
        }
    }

    public static function unschedule(): void
    {
        $timestamp = wp_next_scheduled(self::CRON_HOOK);
        if ($timestamp) {
            wp_unschedule_event($timestamp, self::CRON_HOOK);
        }
    }

    public static function handleScheduledScan(): void
    {
        // This is the action the cron job will trigger.
        // We can instantiate Integrity and run the scan.
        $logger = new \MordenSecurity\Core\LoggerSQLite();
        $integrity = new Integrity($logger);
        $integrity->startScan();
    }
}
