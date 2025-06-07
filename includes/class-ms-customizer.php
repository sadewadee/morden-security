<?php
if (!defined('ABSPATH')) {
    exit;
}

class MS_Customizer {

    private static $instance = null;
    private $core;

    public static function get_instance() {
        if (null === self::$instance) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    private function __construct() {
        $this->core = MS_Core::get_instance();
        $this->ms_init_customizations();
    }

    private function ms_init_customizations() {
        // Hide WordPress version
        if ($this->core->ms_get_option('hide_wp_version', 1)) {
            remove_action('wp_head', 'wp_generator');
            add_filter('the_generator', '__return_empty_string');
            add_filter('style_loader_src', array($this, 'ms_remove_version_strings'), 9999);
            add_filter('script_loader_src', array($this, 'ms_remove_version_strings'), 9999);
        }

        // Remove WordPress credit
        if ($this->core->ms_get_option('remove_wp_credit', 1)) {
            add_filter('admin_footer_text', array($this, 'ms_remove_footer_credit'));
            add_filter('update_footer', array($this, 'ms_remove_footer_version'), 11);
        }

        // Hide WordPress logo
        if ($this->core->ms_get_option('hide_wp_logo', 1)) {
            add_action('wp_before_admin_bar_render', array($this, 'ms_remove_wp_logo'));
            add_action('admin_bar_menu', array($this, 'ms_remove_admin_bar_items'), 999);
        }

        // Hide admin bar for non-admins
        if ($this->core->ms_get_option('hide_admin_bar', 1)) {
            add_action('after_setup_theme', array($this, 'ms_hide_admin_bar'));
        }

        // Custom login modifications
        add_action('login_enqueue_scripts', array($this, 'ms_custom_login_styles'));
        add_filter('login_headerurl', array($this, 'ms_custom_login_logo_url'));
        add_filter('login_headertext', array($this, 'ms_custom_login_logo_title'));
        add_action('login_footer', array($this, 'ms_custom_login_footer'));

        // Remove unnecessary WordPress features
        add_action('init', array($this, 'ms_remove_wp_features'));

        // Clean up WordPress head
        add_action('init', array($this, 'ms_cleanup_wp_head'));

        // Custom admin dashboard
        add_action('wp_dashboard_setup', array($this, 'ms_custom_dashboard_widgets'));

        // Remove update notifications for non-admins
        add_action('admin_head', array($this, 'ms_hide_update_notices'));

        // Custom admin footer
        add_action('admin_enqueue_scripts', array($this, 'ms_admin_custom_styles'));
    }

    public function ms_remove_version_strings($src) {
        if (strpos($src, 'ver=')) {
            $src = remove_query_arg('ver', $src);
        }
        return $src;
    }

    public function ms_remove_footer_credit() {
        return '<span id="footer-thankyou">' .
               sprintf(__('Secured by %s', 'morden-security'),
                      '<strong>Morden Security</strong>') .
               '</span>';
    }

    public function ms_remove_footer_version() {
        return '<span class="ms-version">' .
               sprintf(__('Morden Security v%s', 'morden-security'), MS_VERSION) .
               '</span>';
    }

    public function ms_remove_wp_logo() {
        global $wp_admin_bar;
        $wp_admin_bar->remove_menu('wp-logo');
        $wp_admin_bar->remove_menu('about');
        $wp_admin_bar->remove_menu('wporg');
        $wp_admin_bar->remove_menu('documentation');
        $wp_admin_bar->remove_menu('support-forums');
        $wp_admin_bar->remove_menu('feedback');
    }

    public function ms_remove_admin_bar_items() {
        global $wp_admin_bar;

        if (!current_user_can('administrator')) {
            $wp_admin_bar->remove_menu('comments');
            $wp_admin_bar->remove_menu('new-content');
            $wp_admin_bar->remove_menu('updates');
        }
    }

    public function ms_hide_admin_bar() {
        if (!current_user_can('administrator') && !is_admin()) {
            show_admin_bar(false);
        }
    }

    public function ms_custom_login_styles() {
        wp_enqueue_style('ms-login-style', MS_PLUGIN_URL . 'public/css/login-style.css', array(), MS_VERSION);
        ?>
        <style type="text/css">
            #login h1 a, .login h1 a {
                background-image: url(<?php echo esc_url(MS_PLUGIN_URL . 'admin/images/logo.png'); ?>);
                height: 80px;
                width: 320px;
                background-size: contain;
                background-repeat: no-repeat;
                background-position: center;
                padding-bottom: 30px;
            }

            .login {
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            }

            .login form {
                border-radius: 8px;
                box-shadow: 0 10px 30px rgba(0,0,0,0.3);
            }

            .login #nav a, .login #backtoblog a {
                color: #fff !important;
                text-shadow: 1px 1px 2px rgba(0,0,0,0.5);
            }

            .login #nav a:hover, .login #backtoblog a:hover {
                color: #f0f0f0 !important;
            }
        </style>
        <?php
    }

    public function ms_custom_login_logo_url() {
        return home_url();
    }

    public function ms_custom_login_logo_title() {
        return get_bloginfo('name') . ' - ' . __('Secured by Morden Security', 'morden-security');
    }

    public function ms_custom_login_footer() {
        ?>
        <div class="ms-login-footer">
            <p><?php printf(__('Protected by %s', 'morden-security'), '<strong>Morden Security</strong>'); ?></p>
        </div>
        <style>
            .ms-login-footer {
                text-align: center;
                margin-top: 20px;
                color: #fff;
                text-shadow: 1px 1px 2px rgba(0,0,0,0.5);
            }
        </style>
        <?php
    }

    public function ms_remove_wp_features() {
        // Remove unnecessary features for security
        remove_action('wp_head', 'rsd_link');
        remove_action('wp_head', 'wlwmanifest_link');
        remove_action('wp_head', 'wp_shortlink_wp_head');
        remove_action('wp_head', 'adjacent_posts_rel_link_wp_head');
        remove_action('wp_head', 'feed_links_extra', 3);
        remove_action('wp_head', 'wp_resource_hints', 2);

        // Disable pingbacks
        add_filter('xmlrpc_methods', array($this, 'ms_disable_pingbacks'));
        add_filter('wp_headers', array($this, 'ms_remove_x_pingback'));

        // Remove REST API links
        remove_action('wp_head', 'rest_output_link_wp_head');
        remove_action('wp_head', 'wp_oembed_add_discovery_links');
        remove_action('template_redirect', 'rest_output_link_header', 11);

        // Disable embeds
        add_action('wp_footer', array($this, 'ms_deregister_embed_scripts'));
    }

    public function ms_disable_pingbacks($methods) {
        unset($methods['pingback.ping']);
        unset($methods['pingback.extensions.getPingbacks']);
        return $methods;
    }

    public function ms_remove_x_pingback($headers) {
        unset($headers['X-Pingback']);
        return $headers;
    }

    public function ms_deregister_embed_scripts() {
        wp_deregister_script('wp-embed');
    }

    public function ms_cleanup_wp_head() {
        // Remove DNS prefetch
        remove_action('wp_head', 'wp_resource_hints', 2);

        // Remove emoji scripts and styles
        remove_action('wp_head', 'print_emoji_detection_script', 7);
        remove_action('wp_print_styles', 'print_emoji_styles');
        remove_action('admin_print_scripts', 'print_emoji_detection_script');
        remove_action('admin_print_styles', 'print_emoji_styles');

        // Remove block library CSS for non-block themes
        if (!current_theme_supports('wp-block-styles')) {
            wp_dequeue_style('wp-block-library');
            wp_dequeue_style('wp-block-library-theme');
        }
    }

    public function ms_custom_dashboard_widgets() {
        // Remove default dashboard widgets
        remove_meta_box('dashboard_incoming_links', 'dashboard', 'normal');
        remove_meta_box('dashboard_plugins', 'dashboard', 'normal');
        remove_meta_box('dashboard_primary', 'dashboard', 'side');
        remove_meta_box('dashboard_secondary', 'dashboard', 'normal');
        remove_meta_box('dashboard_quick_press', 'dashboard', 'side');
        remove_meta_box('dashboard_recent_drafts', 'dashboard', 'side');

        // Add custom security dashboard widget
        wp_add_dashboard_widget(
            'ms_security_dashboard',
            __('Morden Security Status', 'morden-security'),
            array($this, 'ms_security_dashboard_widget')
        );
    }

    public function ms_security_dashboard_widget() {
        global $wpdb;

        // Get recent security stats
        $login_table = $wpdb->prefix . 'ms_login_attempts';
        $log_table = $wpdb->prefix . 'ms_security_log';
        $blocked_table = $wpdb->prefix . 'ms_blocked_ips';

        $recent_attempts = $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM $login_table WHERE last_attempt > %s",
            date('Y-m-d H:i:s', strtotime('-24 hours'))
        ));

        $recent_events = $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM $log_table WHERE created_at > %s",
            date('Y-m-d H:i:s', strtotime('-24 hours'))
        ));

        $blocked_ips = $wpdb->get_var("SELECT COUNT(*) FROM $blocked_table");

        ?>
        <div class="ms-dashboard-widget">
            <div class="ms-security-stats">
                <div class="ms-stat-item">
                    <span class="ms-stat-label"><?php _e('Login Attempts (24h)', 'morden-security'); ?></span>
                    <span class="ms-stat-value"><?php echo esc_html($recent_attempts); ?></span>
                </div>
                <div class="ms-stat-item">
                    <span class="ms-stat-label"><?php _e('Security Events (24h)', 'morden-security'); ?></span>
                    <span class="ms-stat-value"><?php echo esc_html($recent_events); ?></span>
                </div>
                <div class="ms-stat-item">
                    <span class="ms-stat-label"><?php _e('Blocked IPs', 'morden-security'); ?></span>
                    <span class="ms-stat-value"><?php echo esc_html($blocked_ips); ?></span>
                </div>
            </div>
            <div class="ms-dashboard-actions">
                <a href="<?php echo admin_url('admin.php?page=morden-security'); ?>" class="button button-primary">
                    <?php _e('Security Settings', 'morden-security'); ?>
                </a>
                <a href="<?php echo admin_url('admin.php?page=ms-security-logs'); ?>" class="button">
                    <?php _e('View Logs', 'morden-security'); ?>
                </a>
            </div>
        </div>
        <style>
            .ms-dashboard-widget .ms-security-stats {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
                gap: 15px;
                margin-bottom: 15px;
            }
            .ms-stat-item {
                text-align: center;
                padding: 10px;
                background: #f8f9fa;
                border-radius: 4px;
            }
            .ms-stat-label {
                display: block;
                font-size: 12px;
                color: #666;
                margin-bottom: 5px;
            }
            .ms-stat-value {
                display: block;
                font-size: 18px;
                font-weight: bold;
                color: #0073aa;
            }
            .ms-dashboard-actions {
                text-align: center;
            }
            .ms-dashboard-actions .button {
                margin: 0 5px;
            }
        </style>
        <?php
    }

    public function ms_hide_update_notices() {
        if (!current_user_can('administrator')) {
            echo '<style>
                .update-nag, .updated, .error, .is-dismissible { display: none; }
                #wp-admin-bar-updates { display: none !important; }
            </style>';
        }
    }

    public function ms_admin_custom_styles() {
        wp_add_inline_style('admin-bar', '
            #wpadminbar .ab-top-menu > li#wp-admin-bar-wp-logo > .ab-item .ab-icon:before {
                content: "\f332";
                color: #00a32a;
            }
            #footer-thankyou {
                font-weight: bold;
                color: #0073aa;
            }
            .ms-version {
                color: #666;
                font-style: italic;
            }
        ');
    }
}
