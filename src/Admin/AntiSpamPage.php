<?php

namespace MordenSecurity\Admin;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Class AntiSpamPage
 *
 * @package MordenSecurity\Admin
 */
class AntiSpamPage
{
    /**
     * Renders the Anti-Spam settings page.
     */
    public function render(): void
    {
        ?>
        <div class="wrap">
            <h1>Anti-Spam Settings</h1>
            <h2 class="nav-tab-wrapper">
                <a href="#anti-spam" class="nav-tab nav-tab-active">Anti Spam</a>
                <a href="#form-protection" class="nav-tab">Form Protection</a>
                <a href="#info-guide" class="nav-tab">Info</a>
            </h2>

            <form method="post" action="options.php">
                <?php
                settings_fields('ms_anti_spam_settings');
                do_settings_sections('ms_anti_spam_settings');
                ?>

                <div id="anti-spam" class="tab-content">
                    <h3>Anti-Spam Engine</h3>
                    <p>Spam protection for registration, comment, and other forms on the website.</p>
                    <table class="form-table">
                        <tr>
                            <th scope="row">Protect registration form</th>
                            <td><label><input type="checkbox" name="ms_protect_registration" <?php checked(get_option('ms_protect_registration'), 1); ?> value="1"> Protect the standard WordPress registration form with bot detection engine</label></td>
                        </tr>
                        <tr>
                            <th scope="row">Protect comment form</th>
                            <td><label><input type="checkbox" name="ms_protect_comment" <?php checked(get_option('ms_protect_comment'), 1); ?> value="1"> Protect the standard WordPress comment form with bot detection engine</label></td>
                        </tr>
                        <tr>
                            <th scope="row">Protect other forms</th>
                            <td><label><input type="checkbox" name="ms_protect_other_forms" <?php checked(get_option('ms_protect_other_forms'), 1); ?> value="1"> Protect all forms on the website with bot detection engine</label></td>
                        </tr>
                    </table>

                    <h3>Adjust Anti-Spam Engine</h3>
                    <p>These settings enable you to fine-tune the behavior of anti-spam algorithms and avoid false positives.</p>
                    <table class="form-table">
                        <tr>
                            <th scope="row">Disable spam checks for logged-in users</th>
                            <td><label><input type="checkbox" name="ms_disable_for_logged_in" <?php checked(get_option('ms_disable_for_logged_in'), 1); ?> value="1"> Disable spam checks and bot detection engine for logged-in users</label></td>
                        </tr>
                        <tr>
                            <th scope="row">Use White IP Access List</th>
                            <td><label><input type="checkbox" name="ms_use_ip_whitelist" <?php checked(get_option('ms_use_ip_whitelist'), 1); ?> value="1"> Disable bot detection engine for IP addresses in the White IP Access List</label></td>
                        </tr>
                        <tr>
                            <th scope="row">Exclude these locations from scanning for spam</th>
                            <td><textarea name="ms_exclude_locations" rows="5" cols="50" class="large-text"><?php echo esc_textarea(get_option('ms_exclude_locations')); ?></textarea></td>
                        </tr>
                        <tr>
                            <th scope="row">Exclude requests with these HTTP headers from scanning for spam</th>
                            <td><textarea name="ms_exclude_headers" rows="5" cols="50" class="large-text"><?php echo esc_textarea(get_option('ms_exclude_headers')); ?></textarea></td>
                        </tr>
                    </table>

                    <h3>Comment Processing</h3>
                    <table class="form-table">
                        <tr>
                            <th scope="row">If a spam comment detected</th>
                            <td>
                                <select name="ms_spam_action">
                                    <option value="deny" <?php selected(get_option('ms_spam_action'), 'deny'); ?>>Deny it completely</option>
                                    <option value="trash" <?php selected(get_option('ms_spam_action'), 'trash'); ?>>Move spam comments to trash</option>
                                </select>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row">Trash spam comments</th>
                            <td><label><input type="checkbox" name="ms_trash_spam" <?php checked(get_option('ms_trash_spam'), 1); ?> value="1"> Move spam comments to trash after <input type="number" name="ms_trash_days" value="<?php echo esc_attr(get_option('ms_trash_days', 7)); ?>" min="1" style="width: 60px;"> days</label></td>
                        </tr>
                    </table>
                </div>

                <div id="form-protection" class="tab-content" style="display: none;">
                    <h3>Form Protection Service</h3>
                    <p>Select a service to protect your forms from spam bots. Only one can be active at a time.</p>
                    <table class="form-table">
                        <tr>
                            <th scope="row">Select Service</th>
                            <td>
                                <fieldset>
                                    <label><input type="radio" name="ms_form_protection_service" value="" <?php checked(get_option('ms_form_protection_service', ''), ''); ?>> None (Disabled)</label><br>
                                    <label><input type="radio" name="ms_form_protection_service" value="recaptcha" <?php checked(get_option('ms_form_protection_service'), 'recaptcha'); ?>> Google reCAPTCHA</label><br>
                                    <label><input type="radio" name="ms_form_protection_service" value="turnstile" <?php checked(get_option('ms_form_protection_service'), 'turnstile'); ?>> Cloudflare Turnstile</label>
                                </fieldset>
                            </td>
                        </tr>
                    </table>

                    <div id="recaptcha-settings-wrapper" style="display:none;">
                        <h3>reCAPTCHA Settings</h3>
                        <table class="form-table">
                            <tr>
                                <th scope="row">Site key</th>
                                <td><input type="text" name="ms_recaptcha_site_key" value="<?php echo esc_attr(get_option('ms_recaptcha_site_key')); ?>" class="regular-text"></td>
                            </tr>
                            <tr>
                                <th scope="row">Secret key</th>
                                <td><input type="text" name="ms_recaptcha_secret_key" value="<?php echo esc_attr(get_option('ms_recaptcha_secret_key')); ?>" class="regular-text"></td>
                            </tr>
                        </table>
                    </div>

                    <div id="turnstile-settings-wrapper" style="display:none;">
                        <h3>Cloudflare Turnstile Settings</h3>
                        <table class="form-table">
                            <tr>
                                <th scope="row">Site key</th>
                                <td><input type="text" name="ms_turnstile_site_key" value="<?php echo esc_attr(get_option('ms_turnstile_site_key')); ?>" class="regular-text"></td>
                            </tr>
                            <tr>
                                <th scope="row">Secret key</th>
                                <td><input type="text" name="ms_turnstile_secret_key" value="<?php echo esc_attr(get_option('ms_turnstile_secret_key')); ?>" class="regular-text"></td>
                            </tr>
                        </table>
                    </div>
                </div>

                <div id="info-guide" class="tab-content" style="display: none;">
                    <h3>How to get Google reCAPTCHA v2 Keys</h3>
                    <ol>
                        <li>Go to the <a href="https://www.google.com/recaptcha/admin/create" target="_blank">reCAPTCHA admin console</a>.</li>
                        <li>Register your site. Use <strong>reCAPTCHA v2</strong>, and choose the "I'm not a robot" Checkbox option.</li>
                        <li>Add your domain name(s) where the plugin will be used.</li>
                        <li>Accept the terms of service and click "Submit".</li>
                        <li>Copy the "Site Key" and "Secret Key" into the fields under the "Form Protection" tab.</li>
                    </ol>

                    <h3>How to get Cloudflare Turnstile Keys</h3>
                    <ol>
                        <li>Log in to your <a href="https://dash.cloudflare.com/" target="_blank">Cloudflare dashboard</a>.</li>
                        <li>In the navigation menu, go to <strong>Turnstile</strong>.</li>
                        <li>Click "Add site" and give your site a name.</li>
                        <li>Enter your domain name and select the "Managed" widget type.</li>
                        <li>Click "Create".</li>
                        <li>Copy the "Site Key" and "Secret Key" into the fields under the "Form Protection" tab.</li>
                    </ol>
                </div>

                <?php submit_button(); ?>
            </form>
        </div>
        <style>
            .tab-content {
                display: none;
            }
            .tab-content.active {
                display: block;
            }
        </style>
        <script>
            document.addEventListener('DOMContentLoaded', function() {
                const tabs = document.querySelectorAll('.nav-tab');
                const tabContents = document.querySelectorAll('.tab-content');

                tabs.forEach(tab => {
                    tab.addEventListener('click', function(e) {
                        e.preventDefault();

                        tabs.forEach(t => t.classList.remove('nav-tab-active'));
                        this.classList.add('nav-tab-active');

                        tabContents.forEach(c => c.style.display = 'none');
                        document.querySelector(this.getAttribute('href')).style.display = 'block';
                    });
                });

                // Show the first tab by default
                document.querySelector('.nav-tab').click();
            });
        </script>
        <?php
    }
}
