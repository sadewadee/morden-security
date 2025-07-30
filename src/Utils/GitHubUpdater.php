<?php

namespace MordenSecurity\Utils;

if (!defined('ABSPATH')) {
    exit;
}

class GitHubUpdater
{
    private string $pluginFile;
    private string $pluginSlug;
    private string $version;
    private string $githubRepo;
    private string $githubToken;

    public function __construct()
    {
        $this->pluginFile = MS_PLUGIN_FILE;
        $this->pluginSlug = MS_PLUGIN_BASENAME;
        $this->version = MS_PLUGIN_VERSION;
        $this->githubRepo = MS_GITHUB_REPO;
        $this->githubToken = get_option('ms_github_token', '');

        $this->initializeHooks();
    }

    public function checkForUpdates(): ?array
    {
        $remoteVersion = $this->getRemoteVersion();

        if (!$remoteVersion) {
            return null;
        }

        if (version_compare($this->version, $remoteVersion['version'], '<')) {
            return [
                'current_version' => $this->version,
                'new_version' => $remoteVersion['version'],
                'download_url' => $remoteVersion['download_url'],
                'changelog' => $remoteVersion['changelog'],
                'tested_up_to' => $remoteVersion['tested_up_to'] ?? '',
                'requires_php' => $remoteVersion['requires_php'] ?? MS_MIN_PHP_VERSION
            ];
        }

        return null;
    }

    public function downloadUpdate(string $downloadUrl): string
    {
        $tempFile = download_url($downloadUrl);

        if (is_wp_error($tempFile)) {
            throw new Exception('Failed to download update: ' . $tempFile->get_error_message());
        }

        return $tempFile;
    }

    public function installUpdate(string $packageFile): bool
    {
        require_once ABSPATH . 'wp-admin/includes/class-wp-upgrader.php';
        require_once ABSPATH . 'wp-admin/includes/plugin-install.php';

        $upgrader = new Plugin_Upgrader();
        $result = $upgrader->install($packageFile);

        if (is_wp_error($result)) {
            error_log('MS Update Error: ' . $result->get_error_message());
            return false;
        }

        return $result;
    }

    private function initializeHooks(): void
    {
        add_filter('plugins_api', [$this, 'pluginInfo'], 20, 3);
        add_filter('site_transient_update_plugins', [$this, 'updateCheck']);
        add_filter('upgrader_pre_download', [$this, 'preDownload'], 10, 3);

        if (!wp_next_scheduled('ms_check_updates')) {
            wp_schedule_event(time(), 'twicedaily', 'ms_check_updates');
        }

        add_action('ms_check_updates', [$this, 'scheduledUpdateCheck']);
    }

    public function pluginInfo($result, $action, $args)
    {
        if ($action !== 'plugin_information' || $args->slug !== dirname($this->pluginSlug)) {
            return $result;
        }

        $remoteVersion = $this->getRemoteVersion();

        if (!$remoteVersion) {
            return $result;
        }

        return (object) [
            'name' => 'Morden Security',
            'slug' => dirname($this->pluginSlug),
            'version' => $remoteVersion['version'],
            'author' => 'Morden Team',
            'homepage' => 'https://github.com/' . $this->githubRepo,
            'download_link' => $remoteVersion['download_url'],
            'sections' => [
                'description' => 'Advanced WordPress security plugin with AI-powered threat detection.',
                'changelog' => $remoteVersion['changelog']
            ],
            'tested' => $remoteVersion['tested_up_to'] ?? '',
            'requires_php' => $remoteVersion['requires_php'] ?? MS_MIN_PHP_VERSION
        ];
    }

    public function updateCheck($transient)
    {
        if (empty($transient->checked)) {
            return $transient;
        }

        $updateInfo = $this->checkForUpdates();

        if ($updateInfo) {
            $transient->response[$this->pluginSlug] = (object) [
                'slug' => dirname($this->pluginSlug),
                'new_version' => $updateInfo['new_version'],
                'url' => 'https://github.com/' . $this->githubRepo,
                'package' => $updateInfo['download_url']
            ];
        }

        return $transient;
    }

    public function preDownload($reply, $package, $upgrader)
    {
        if (strpos($package, 'github.com') === false) {
            return $reply;
        }

        $downloadFile = $this->downloadUpdate($package);

        if ($downloadFile) {
            return $downloadFile;
        }

        return new WP_Error('download_failed', 'Failed to download from GitHub');
    }

    public function scheduledUpdateCheck(): void
    {
        $updateInfo = $this->checkForUpdates();

        if ($updateInfo) {
            update_option('ms_update_available', $updateInfo);

            if (get_option('ms_auto_updates_enabled', false)) {
                $this->performAutoUpdate($updateInfo);
            }
        }
    }

    private function getRemoteVersion(): ?array
    {
        $apiUrl = MS_GITHUB_API_URL . '/releases/latest';
        $args = ['timeout' => 30];

        if ($this->githubToken) {
            $args['headers'] = ['Authorization' => 'token ' . $this->githubToken];
        }

        $response = wp_remote_get($apiUrl, $args);

        if (is_wp_error($response)) {
            return null;
        }

        $body = wp_remote_retrieve_body($response);
        $data = json_decode($body, true);

        if (!$data || !isset($data['tag_name'])) {
            return null;
        }

        return [
            'version' => ltrim($data['tag_name'], 'v'),
            'download_url' => $data['zipball_url'],
            'changelog' => $data['body'] ?? '',
            'tested_up_to' => $this->extractTestedUpTo($data['body'] ?? ''),
            'requires_php' => $this->extractRequiresPhp($data['body'] ?? '')
        ];
    }

    private function extractTestedUpTo(string $changelog): string
    {
        if (preg_match('/tested.+?(\d+\.\d+)/i', $changelog, $matches)) {
            return $matches[1];
        }
        return get_bloginfo('version');
    }

    private function extractRequiresPhp(string $changelog): string
    {
        if (preg_match('/php.+?(\d+\.\d+)/i', $changelog, $matches)) {
            return $matches[1];
        }
        return MS_MIN_PHP_VERSION;
    }

    private function performAutoUpdate(array $updateInfo): bool
    {
        try {
            $packageFile = $this->downloadUpdate($updateInfo['download_url']);
            $result = $this->installUpdate($packageFile);

            if ($result) {
                update_option('ms_last_auto_update', time());
                delete_option('ms_update_available');
            }

            return $result;
        } catch (Exception $e) {
            error_log('MS Auto-update failed: ' . $e->getMessage());
            return false;
        }
    }
}
