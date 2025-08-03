<?php

namespace MordenSecurity\Modules\Hardening;

if (!defined('ABSPATH')) {
    exit;
}

class WordPressHardening
{
    private array $config;
    private string $htaccessPath;
    private string $uploadsDir;
    private string $wpConfigPath;

    public function __construct()
    {
        $uploadDir = wp_upload_dir();
        $this->uploadsDir = $uploadDir['basedir'];
        $this->htaccessPath = ABSPATH . '.htaccess';
        $this->wpConfigPath = ABSPATH . 'wp-config.php';

        $this->loadConfiguration();
        $this->initializeHooks();
        $this->applyHardeningMeasures();
    }

    private function loadConfiguration(): void
    {
        $this->config = [
            'hide_wp_version' => get_option('ms_hide_wp_version', true),
            'disable_xmlrpc' => get_option('ms_disable_xmlrpc', true),
            'protect_config' => get_option('ms_protect_config', true),
            'restrict_file_edit' => get_option('ms_restrict_file_edit', true),
            'sanitize_headers' => get_option('ms_sanitize_headers', true),
            'disable_php_in_uploads' => get_option('ms_disable_php_in_uploads', true),
            'disable_directory_browsing' => get_option('ms_disable_directory_browsing', true),
            'disable_user_enumeration' => get_option('ms_disable_user_enumeration', true),
            'hide_wp_file_structure' => get_option('ms_hide_wp_file_structure', true),
            'remove_generator_meta' => get_option('ms_remove_generator_meta', true),
            'disable_file_execution' => get_option('ms_disable_file_execution', true),
            'disable_rest_api' => get_option('ms_disable_rest_api', true),
            'remove_rsd_link' => get_option('ms_remove_rsd_link', true),
            'disable_pingbacks' => get_option('ms_disable_pingbacks', true),
        ];
    }

    private function initializeHooks(): void
    {
        if ($this->config['restrict_file_edit']) {
            $this->enforceFileEditorDisabling();
        }

        if ($this->config['hide_wp_version']) {
            add_filter('the_generator', '__return_empty_string', 99);
            remove_action('wp_head', 'wp_generator');
        }

        if ($this->config['disable_xmlrpc']) {
            add_filter('xmlrpc_enabled', '__return_false');
            add_filter('wp_headers', [$this, 'removeXmlrpcHeaders']);
        }

        if ($this->config['disable_pingbacks']) {
            add_filter('wp_headers', [$this, 'removePingbackHeaders']);
            add_filter('xmlrpc_methods', [$this, 'disableXmlrpcPingbacks']);
        }

        if ($this->config['sanitize_headers']) {
            add_action('send_headers', [$this, 'sanitizeHeaders'], 99);
        }

        if ($this->config['disable_user_enumeration']) {
            add_action('init', [$this, 'disableUserEnumeration']);
            add_filter('redirect_canonical', [$this, 'disableAuthorPages'], 10, 2);
        }

        if ($this->config['remove_generator_meta']) {
            remove_action('wp_head', 'wp_generator');
            add_filter('the_generator', '__return_empty_string');
        }

        if ($this->config['disable_rest_api']) {
            add_filter('rest_authentication_errors', [$this, 'disableRestApi']);
        }

        if ($this->config['remove_rsd_link']) {
            remove_action('wp_head', 'rsd_link');
            remove_action('wp_head', 'wlwmanifest_link');
        }

        if ($this->config['hide_wp_file_structure']) {
            add_filter('style_loader_src', [$this, 'hideWpPaths'], 99);
            add_filter('script_loader_src', [$this, 'hideWpPaths'], 99);
        }

        add_action('admin_menu', [$this, 'removeEditorMenus'], 99);
        add_action('update_option_ms_restrict_file_edit', [$this, 'toggleFileEditorSetting'], 10, 2);
        register_deactivation_hook(MS_PLUGIN_FILE, [$this, 'cleanup']);
    }

    private function enforceFileEditorDisabling(): void
    {
        if (!defined('DISALLOW_FILE_EDIT')) {
            define('DISALLOW_FILE_EDIT', true);
        }

        $this->updateWpConfig('DISALLOW_FILE_EDIT', true);
        add_action('admin_init', [$this, 'removeFileEditCapabilities']);
    }

    public function toggleFileEditorSetting($oldValue, $newValue): void
    {
        $this->updateWpConfig('DISALLOW_FILE_EDIT', $newValue);
    }

    public function removeEditorMenus(): void
    {
        if ($this->config['restrict_file_edit']) {
            remove_submenu_page('themes.php', 'theme-editor.php');
            remove_submenu_page('plugins.php', 'plugin-editor.php');
        }
    }

    public function removeFileEditCapabilities(): void
    {
        $roles = ['administrator', 'editor', 'author'];

        foreach ($roles as $roleName) {
            $role = get_role($roleName);
            if ($role) {
                $role->remove_cap('edit_themes');
                $role->remove_cap('edit_plugins');
            }
        }
    }

    private function applyHardeningMeasures(): void
    {
        if ($this->config['protect_config']) {
            $this->protectConfigFiles();
        }

        if ($this->config['disable_php_in_uploads']) {
            $this->disablePhpInUploads();
        }

        if ($this->config['disable_directory_browsing']) {
            $this->disableDirectoryBrowsing();
        }

        if ($this->config['disable_file_execution']) {
            $this->disableFileExecution();
        }
    }

    private function updateWpConfig(string $constant, $value): bool
    {
        if (!file_exists($this->wpConfigPath)) {
            return false;
        }

        $originalPermissions = $this->getFilePermissions($this->wpConfigPath);

        if (!$this->makeFileWritable($this->wpConfigPath)) {
            return false;
        }

        $configContent = file_get_contents($this->wpConfigPath);

        if ($this->constantExistsInConfig($configContent, $constant)) {
            $this->restoreFilePermissions($this->wpConfigPath, $originalPermissions);
            return true;
        }

        $valueString = $value ? 'true' : 'false';
        $newConstant = "define('{$constant}', {$valueString});\n";

        $insertPoints = [
            "/* That's all, stop editing! Happy publishing. */",
            "/* That's all, stop editing! Happy blogging. */",
            "require_once ABSPATH . 'wp-settings.php';"
        ];

        $inserted = false;
        foreach ($insertPoints as $insertPoint) {
            if (strpos($configContent, $insertPoint) !== false) {
                $configContent = str_replace(
                    $insertPoint,
                    $newConstant . $insertPoint,
                    $configContent
                );
                $inserted = true;
                break;
            }
        }

        if (!$inserted) {
            $configContent .= "\n" . $newConstant;
        }

        $result = file_put_contents($this->wpConfigPath, $configContent, LOCK_EX) !== false;
        $this->restoreFilePermissions($this->wpConfigPath, $originalPermissions);

        return $result;
    }

    private function getFilePermissions(string $filePath): ?int
    {
        if (!file_exists($filePath)) {
            return null;
        }

        return fileperms($filePath) & 0777;
    }

    private function makeFileWritable(string $filePath): bool
    {
        if (!file_exists($filePath)) {
            return false;
        }

        if (is_writable($filePath)) {
            return true;
        }

        $currentPerms = $this->getFilePermissions($filePath);
        if ($currentPerms === null) {
            return false;
        }

        return chmod($filePath, $currentPerms | 0200);
    }

    private function restoreFilePermissions(string $filePath, ?int $permissions): bool
    {
        if ($permissions === null || !file_exists($filePath)) {
            return false;
        }

        return chmod($filePath, $permissions);
    }

    private function constantExistsInConfig(string $content, string $constant): bool
    {
        $patterns = [
            "/define\s*\(\s*['\"]" . preg_quote($constant, '/') . "['\"]\s*,\s*true\s*\)/",
            "/define\s*\(\s*['\"]" . preg_quote($constant, '/') . "['\"]\s*,\s*1\s*\)/"
        ];

        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $content)) {
                return true;
            }
        }

        return false;
    }

    public function protectConfigFiles(): void
    {
        $htaccessRules = "\n<files wp-config.php>\n" .
                        "    order allow,deny\n" .
                        "    deny from all\n" .
                        "</files>\n" .
                        "<files wp-config-sample.php>\n" .
                        "    order allow,deny\n" .
                        "    deny from all\n" .
                        "</files>\n\n";

        $this->addHtaccessRules($htaccessRules, 'Morden Security Config Protection');
    }

    public function disablePhpInUploads(): void
    {
        $uploadsHtaccess = $this->uploadsDir . '/.htaccess';
        $rules = "<Files \"*.php\">\n" .
                "    Order Deny,Allow\n" .
                "    Deny from all\n" .
                "</Files>\n" .
                "<Files \"*.php3\">\n" .
                "    Order Deny,Allow\n" .
                "    Deny from all\n" .
                "</Files>\n" .
                "<Files \"*.php4\">\n" .
                "    Order Deny,Allow\n" .
                "    Deny from all\n" .
                "</Files>\n" .
                "<Files \"*.php5\">\n" .
                "    Order Deny,Allow\n" .
                "    Deny from all\n" .
                "</Files>\n" .
                "<Files \"*.phtml\">\n" .
                "    Order Deny,Allow\n" .
                "    Deny from all\n" .
                "</Files>\n";

        if ($this->isWritableDirectory(dirname($uploadsHtaccess))) {
            file_put_contents($uploadsHtaccess, $rules, LOCK_EX);
        }
    }

    public function disableDirectoryBrowsing(): void
    {
        $rules = "\nOptions -Indexes\n\n";
        $this->addHtaccessRules($rules, 'Morden Security Directory Browsing Protection');
    }

    public function disableFileExecution(): void
    {
        $htaccessPath = ABSPATH . 'wp-content/uploads/.htaccess';
        $denyRules = "<Files \"*.php\">\n" .
                    "    Order Allow,Deny\n" .
                    "    Deny from all\n" .
                    "</Files>\n" .
                    "<Files \"*.pl\">\n" .
                    "    Order Allow,Deny\n" .
                    "    Deny from all\n" .
                    "</Files>\n" .
                    "<Files \"*.py\">\n" .
                    "    Order Allow,Deny\n" .
                    "    Deny from all\n" .
                    "</Files>\n" .
                    "<Files \"*.cgi\">\n" .
                    "    Order Allow,Deny\n" .
                    "    Deny from all\n" .
                    "</Files>\n";

        if ($this->isWritableFile($htaccessPath)) {
            file_put_contents($htaccessPath, $denyRules, LOCK_EX);
        }
    }

    public function hideWpFileStructure(): void
    {
        add_action('wp_head', function() {
            ob_start(function($buffer) {
                $buffer = str_replace('wp-content', 'resources', $buffer);
                $buffer = str_replace('wp-includes', 'assets', $buffer);
                return $buffer;
            });
        });
    }

    public function hideWpPaths(string $src): string
    {
        $replacements = [
            '/wp-content/' => '/resources/',
            '/wp-includes/' => '/assets/',
            'wp-content' => 'resources',
            'wp-includes' => 'assets'
        ];

        return str_replace(array_keys($replacements), array_values($replacements), $src);
    }

    public function disableUserEnumeration(): void
    {
        if (!is_admin() && isset($_GET['author'])) {
            wp_redirect(home_url(), 301);
            exit;
        }
    }

    public function disableAuthorPages($redirectUrl, $requestedUrl): ?string
    {
        if (preg_match('/\?author=([0-9]*)(\/*)/i', $requestedUrl)) {
            return home_url();
        }
        return $redirectUrl;
    }

    public function disableRestApi($result)
    {
        if (!empty($result)) {
            return $result;
        }

        if (!is_user_logged_in()) {
            return new \WP_Error('rest_not_logged_in', 'You are not currently logged in.', ['status' => 401]);
        }

        return $result;
    }

    public function removeXmlrpcHeaders(array $headers): array
    {
        unset($headers['X-Pingback']);
        return $headers;
    }

    public function removePingbackHeaders(array $headers): array
    {
        unset($headers['X-Pingback']);
        return $headers;
    }

    public function disableXmlrpcPingbacks(array $methods): array
    {
        unset($methods['pingback.ping']);
        unset($methods['pingback.extensions.getPingbacks']);
        return $methods;
    }

    public function sanitizeHeaders(): void
    {
        header_remove('X-Powered-By');
        header_remove('Server');
        header('X-Content-Type-Options: nosniff', true);
        header('X-Frame-Options: SAMEORIGIN', true);
        header('X-XSS-Protection: 1; mode=block', true);
        header('Referrer-Policy: no-referrer-when-downgrade', true);
    }

    private function addHtaccessRules(string $rules, string $identifier): bool
    {
        if (!$this->isWritableFile($this->htaccessPath)) {
            return false;
        }

        $currentContent = file_exists($this->htaccessPath) ? file_get_contents($this->htaccessPath) : '';

        if (strpos($currentContent, $identifier) === false) {
            return file_put_contents($this->htaccessPath, $rules . $currentContent, LOCK_EX) !== false;
        }

        return true;
    }

    private function removeHtaccessRules(string $identifier): void
    {
        $htaccessPath = ABSPATH . '.htaccess';
        if (!file_exists($htaccessPath)) {
            return;
        }

        $content = file_get_contents($htaccessPath);
        $pattern = "/\n# {$identifier}.*?# End {$identifier}\n/s";
        $content = preg_replace($pattern, '', $content);
        file_put_contents($htaccessPath, $content);
    }

    private function isWritableFile(string $filePath): bool
    {
        return (file_exists($filePath) && is_writable($filePath)) ||
               (!file_exists($filePath) && is_writable(dirname($filePath)));
    }

    private function isWritableDirectory(string $dirPath): bool
    {
        return is_dir($dirPath) && is_writable($dirPath);
    }

    public function cleanup(): void
    {
        $this->updateWpConfig('DISALLOW_FILE_EDIT', false);
        $this->removeHtaccessRules('Morden Security Config Protection');
        $this->removeHtaccessRules('Morden Security PHP Execution Protection');
        $this->removeHtaccessRules('Morden Security Directory Browsing Protection');
        $this->removeHtaccessRules('Morden Security File Execution Protection');
        $this->restoreFileEditCapabilities();
    }

    private function restoreFileEditCapabilities(): void
    {
        $roles = ['administrator'];

        foreach ($roles as $roleName) {
            $role = get_role($roleName);
            if ($role) {
                $role->add_cap('edit_themes');
                $role->add_cap('edit_plugins');
            }
        }
    }

    private function removeConstantFromWpConfig(string $constant): bool
    {
        if (!file_exists($this->wpConfigPath)) {
            return false;
        }

        $originalPermissions = $this->getFilePermissions($this->wpConfigPath);

        if (!$this->makeFileWritable($this->wpConfigPath)) {
            return false;
        }

        $configContent = file_get_contents($this->wpConfigPath);
        $pattern = "/define\s*\(\s*['\"]" . preg_quote($constant, '/') . "['\"].*?;.*?\n/";
        $cleanedContent = preg_replace($pattern, '', $configContent);

        $result = file_put_contents($this->wpConfigPath, $cleanedContent, LOCK_EX) !== false;
        $this->restoreFilePermissions($this->wpConfigPath, $originalPermissions);

        return $result;
    }
}
