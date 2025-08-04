<?php

namespace MordenSecurity\Admin;

use MordenSecurity\Core\LoggerSQLite;
use MordenSecurity\Core\SecurityCore;
use MordenSecurity\Admin\IntegrityCheckPage;
use MordenSecurity\Admin\AntiSpamPage;

class AdminController
{
    private Dashboard $dashboard;
    private RequestAnalyzerPage $requestAnalyzerPage;
    private BotDetectionPage $botDetectionPage;
    private CountryManagementPage $countryManagementPage;
    private IntegrityCheckPage $integrityCheckPage;
    private AntiSpamPage $antiSpamPage;

    public function __construct() {
        $logger = new LoggerSQLite();
        $securityCore = new SecurityCore($logger);
        $this->dashboard = new Dashboard($logger, $securityCore);
        $this->requestAnalyzerPage = new RequestAnalyzerPage($logger);
        $this->botDetectionPage = new BotDetectionPage($logger);
        $this->countryManagementPage = new CountryManagementPage($logger);
        $this->integrityCheckPage = new IntegrityCheckPage();
        $this->antiSpamPage = new AntiSpamPage();

        add_action('admin_menu', [$this, 'addAdminMenu']);
        add_action('admin_enqueue_scripts', [$this, 'enqueueAdminScripts']);
        add_action('admin_init', [$this, 'registerSettings']);
    }

    public function addAdminMenu(): void {
        add_menu_page(
            __('Morden Security', 'morden-security'),
            __('Morden Security', 'morden-security'),
            'manage_options',
            'morden-security',
            [$this->dashboard, 'render'],
            'dashicons-shield-alt',
            20
        );

        add_submenu_page(
            'morden-security',
            __('Dashboard', 'morden-security'),
            __('Dashboard', 'morden-security'),
            'manage_options',
            'morden-security',
            [$this->dashboard, 'render']
        );

        add_submenu_page(
            'morden-security',
            __('Request Analyzer', 'morden-security'),
            __('Request Analyzer', 'morden-security'),
            'manage_options',
            'ms-request-analyzer',
            [$this->requestAnalyzerPage, 'render']
        );

        add_submenu_page(
            'morden-security',
            __('Bot Detection', 'morden-security'),
            __('Bot Detection', 'morden-security'),
            'manage_options',
            'ms-bots',
            [$this->botDetectionPage, 'render']
        );

        add_submenu_page(
            'morden-security',
            __('Country Management', 'morden-security'),
            __('Country Management', 'morden-security'),
            'manage_options',
            'ms-countries',
            [$this->countryManagementPage, 'render']
        );

        add_submenu_page(
            'morden-security',
            __('Integrity Check', 'morden-security'),
            __('Integrity Check', 'morden-security'),
            'manage_options',
            'ms-integrity-check',
            [$this->integrityCheckPage, 'render']
        );

        add_submenu_page(
            'morden-security',
            __('Anti Spam', 'morden-security'),
            __('Anti Spam', 'morden-security'),
            'manage_options',
            'ms-anti-spam',
            [$this->antiSpamPage, 'render']
        );
    }

    public function enqueueAdminScripts($hook): void {
        // General admin styles and scripts
        if (strpos($hook, 'morden-security') !== false) {
            wp_enqueue_style('morden-security-admin', MS_PLUGIN_URL . 'assets/css/admin-dashboard.css', [], MS_PLUGIN_VERSION);
            wp_enqueue_script('morden-security-admin', MS_PLUGIN_URL . 'assets/js/admin-dashboard.js', ['jquery'], MS_PLUGIN_VERSION, true);

            wp_localize_script('morden-security-admin', 'msAdmin', [
                'ajax_url' => admin_url('admin-ajax.php'),
                'nonce' => wp_create_nonce('ms_ajax_nonce'),
                'restUrl' => rest_url('morden-security/v1/')
            ]);
        }

        // Specific scripts for the Integrity Check page
        if ($hook === 'morden-security_page_ms-integrity-check') {
            wp_enqueue_style('morden-security-integrity-check', MS_PLUGIN_URL . 'assets/css/integrity-check.css', [], MS_PLUGIN_VERSION);
            wp_enqueue_script('morden-security-integrity-check', MS_PLUGIN_URL . 'assets/js/integrity-check.js', ['jquery'], MS_PLUGIN_VERSION, true);
        }

        // Specific scripts for the Anti Spam page
        if ($hook === 'morden-security_page_ms-anti-spam') {
            wp_enqueue_script('morden-security-anti-spam', MS_PLUGIN_URL . 'assets/js/anti-spam.js', [], MS_PLUGIN_VERSION, true);
        }
    }

    public function registerSettings(): void {
        register_setting('ms_anti_spam_settings', 'ms_protect_registration');
        register_setting('ms_anti_spam_settings', 'ms_protect_comment');
        register_setting('ms_anti_spam_settings', 'ms_protect_other_forms');
        register_setting('ms_anti_spam_settings', 'ms_disable_for_logged_in');
        register_setting('ms_anti_spam_settings', 'ms_use_ip_whitelist');
        register_setting('ms_anti_spam_settings', 'ms_exclude_locations');
        register_setting('ms_anti_spam_settings', 'ms_exclude_headers');
        register_setting('ms_anti_spam_settings', 'ms_spam_action');
        register_setting('ms_anti_spam_settings', 'ms_trash_spam');
        register_setting('ms_anti_spam_settings', 'ms_trash_days');
        register_setting('ms_anti_spam_settings', 'ms_form_protection_service');
        register_setting('ms_anti_spam_settings', 'ms_recaptcha_site_key');
        register_setting('ms_anti_spam_settings', 'ms_recaptcha_secret_key');
        register_setting('ms_anti_spam_settings', 'ms_turnstile_site_key');
        register_setting('ms_anti_spam_settings', 'ms_turnstile_secret_key');
    }
}
