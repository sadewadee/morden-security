=== Morden Security ===
Contributors: Mordenhost Team
Tags: security, firewall, brute force, login protection, security headers, cloudflare turnstile, malware protection, ip blocking, wordpress security
Requires at least: 6.1
Tested up to: 6.7.2
Requires PHP: 7.4
Stable tag: 1.0-beta
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Comprehensive WordPress security plugin with advanced protection features including firewall, brute force protection, security headers, and Cloudflare Turnstile integration.

== Description ==

**Morden Security** is a comprehensive WordPress security plugin designed to protect your website from various online threats and attacks. This plugin provides enterprise-level security features while maintaining ease of use and optimal performance.

= 🛡️ Key Security Features =

**Core Security Protection:**
* Disable WordPress file editor for themes and plugins
* Force HTTPS connections across your site
* Disable XML-RPC to prevent brute force attacks
* Add essential security headers automatically
* Real-time malware scanning for uploaded files
* Advanced firewall protection against common attacks

**Login & Access Protection:**
* Intelligent brute force protection with IP blocking
* Configurable login attempt limits and lockout duration
* Cloudflare Turnstile integration (invisible CAPTCHA)
* Real-time login monitoring and alerts
* Automatic cleanup of old attack attempts

**Advanced Firewall:**
* Block suspicious requests and malicious patterns
* SQL injection protection
* XSS (Cross-Site Scripting) prevention
* Directory traversal attack prevention
* Suspicious user agent detection
* Real-time IP blocking system

**WordPress Customization:**
* Hide WordPress version information
* Remove WordPress branding from admin
* Custom login page styling
* Hide admin bar for non-administrators
* Clean up WordPress head section
* Custom security dashboard widget

= 🚀 Why Choose Morden Security? =

**Performance Optimized:**
* Lightweight and fast - won't slow down your website
* Efficient database queries with automatic cleanup
* Minimal resource usage with maximum protection

**User-Friendly:**
* Intuitive admin interface with tabbed settings
* Real-time security statistics dashboard
* Comprehensive security logs with filtering
* One-click IP unblocking functionality

**Developer Friendly:**
* Follows WordPress coding standards
* Extensive hooks and filters for customization
* Clean, well-documented code
* Translation ready with POT file included

**Enterprise Features:**
* Automated security scanning
* Detailed security event logging
* IP whitelist and blacklist management
* Configurable security policies
* GDPR compliant logging system

= 🔧 Cloudflare Turnstile Integration =

Unlike traditional CAPTCHAs that frustrate users, Cloudflare Turnstile provides invisible protection that doesn't interrupt the user experience while effectively blocking bots and automated attacks. Simply get your free API keys from Cloudflare and enable this feature.

= 📊 Security Dashboard =

Monitor your website's security status with:
* Real-time attack statistics
* Login attempt tracking
* Blocked IP addresses management
* Security event timeline
* Quick access to security settings

= 🌐 Translation Ready =

Morden Security is fully translation ready and includes:
* Complete POT file for translators
* Support for RTL languages
* Internationalization best practices
* Context-aware translations

== Installation ==

= Automatic Installation =

1. Log in to your WordPress admin panel
2. Navigate to Plugins → Add New
3. Search for "Morden Security"
4. Click "Install Now" and then "Activate"
5. Go to Settings → Morden Security to configure

= Manual Installation =

1. Download the plugin ZIP file
2. Upload the `morden-security` folder to `/wp-content/plugins/`
3. Activate the plugin through the 'Plugins' menu in WordPress
4. Configure the plugin at Settings → Morden Security

= Configuration =

1. **Basic Security**: Enable core security features
2. **Login Protection**: Configure brute force protection
3. **Firewall**: Set up advanced threat protection
4. **Customization**: Customize WordPress appearance
5. **Turnstile**: Add Cloudflare Turnstile protection (optional)

= Cloudflare Turnstile Setup =

1. Create a free Cloudflare account at cloudflare.com
2. Go to Turnstile section in your Cloudflare dashboard
3. Create a new site and get your Site Key and Secret Key
4. Enter these keys in the Turnstile settings tab
5. Enable Turnstile protection

== Frequently Asked Questions ==

= Will this plugin slow down my website? =

No, Morden Security is designed to be lightweight and efficient. Most security features work at the server level and don't impact page load times. The plugin includes automatic cleanup routines to maintain optimal performance.

= Can I use this with other security plugins? =

While it's technically possible, we recommend using only one comprehensive security plugin to avoid conflicts and redundancy. Morden Security provides all essential security features you need in one plugin.

= What happens if I get locked out? =

If you get locked out due to failed login attempts:
1. Wait for the lockout period to expire (default: 30 minutes)
2. Access your website via FTP and temporarily rename the plugin folder
3. Contact your hosting provider to whitelist your IP address
4. Use the emergency access feature (if configured)

= Is Cloudflare Turnstile really free? =

Yes, Cloudflare Turnstile is completely free to use. You just need a free Cloudflare account to generate the required API keys. There are no usage limits for most websites.

= How do I view security logs? =

Go to your WordPress admin → Morden Security → Security Logs. Here you can view all security events, filter by type and date, and export logs if needed.

= Can I whitelist my IP address? =

Yes, you can manage IP addresses through the Blocked IPs section. You can unblock IPs, add permanent blocks, or configure whitelist rules.

= Does this work with multisite? =

Currently, Morden Security is designed for single-site installations. Multisite support is planned for a future release.

= How often are security scans performed? =

Automatic security scans run twice daily. You can also trigger manual scans from the security dashboard.

= Is the plugin GDPR compliant? =

Yes, Morden Security follows GDPR guidelines. Personal data (like IP addresses) is stored only for security purposes and is automatically cleaned up after 90 days.

== Screenshots ==

1. **Main Security Dashboard** - Overview of security status with real-time statistics
2. **Security Settings** - Comprehensive security configuration options
3. **Login Protection** - Brute force protection and login attempt monitoring
4. **Firewall Settings** - Advanced firewall configuration and rules
5. **Security Logs** - Detailed security event logging and filtering
6. **Blocked IPs Management** - IP blocking and unblocking interface
7. **Cloudflare Turnstile** - Invisible CAPTCHA configuration
8. **Custom Login Page** - Secured and branded login interface
9. **WordPress Customization** - Hide WordPress branding options
10. **Dashboard Widget** - Security status widget in WordPress dashboard

== Changelog ==

= 1.0-beta - 2025-06-08 =
**Initial Beta Release**

**Security Features:**
* Core WordPress security hardening
* Brute force protection with intelligent IP blocking
* Advanced firewall with pattern detection
* Security headers implementation
* Malware scanning for uploaded files
* XML-RPC protection

**Login Protection:**
* Configurable login attempt limits
* IP-based lockout system
* Cloudflare Turnstile integration
* Login monitoring and alerts
* Automatic cleanup of old attempts

**Firewall Protection:**
* SQL injection prevention
* XSS attack protection
* Directory traversal blocking
* Suspicious user agent detection
* Real-time threat blocking

**Interface & Customization:**
* Modern admin interface with tabbed settings
* Real-time security statistics
* WordPress branding customization
* Custom login page styling
* Security dashboard widget

**Monitoring & Logging:**
* Comprehensive security event logging with country and path tracking
* IP blocking management interface
* Security statistics and reporting
* Automated cleanup routines
* Configurable log retention (1-365 days)
* Maximum log limits (100-10000 entries)

**Developer Features:**
* WordPress coding standards compliance
* Extensive hook system
* Translation ready
* Clean, documented code

== Upgrade Notice ==

= 1.0-beta =
Initial beta release of Morden Security. Install now to secure your WordPress website with comprehensive protection features including firewall, brute force protection, and advanced security monitoring.

== Privacy Policy ==

Morden Security is committed to protecting your privacy and follows these principles:

**Data Collection:**
* IP addresses are collected only for security purposes
* Login attempts and security events are logged locally
* No data is sent to external servers (except Cloudflare Turnstile if enabled)

**Data Storage:**
* All security data is stored in your WordPress database
* Automatic cleanup removes old data after configurable retention period
* Data is encrypted where possible

**Data Usage:**
* Security data is used only for protection purposes
* No personal information is shared with third parties
* Users can request data deletion at any time

**Third-Party Services:**
* Cloudflare Turnstile (optional) - subject to Cloudflare's privacy policy
* IP geolocation service (optional) - for country detection in logs

== Support ==

**GitHub Repository:** https://github.com/sadewadee/morden-security

**Support & Bug Reports:** https://github.com/sadewadee/morden-security/issues

**Contact:** support@mordenhost.com

**Documentation:** Visit our comprehensive documentation at: https://mordenhost.com/docs/morden-security

**Premium Support:** For priority support and advanced features: https://mordenhost.com/support

== Contributing ==

We welcome contributions to Morden Security!

**Ways to Contribute:**
* Report bugs and suggest features
* Submit translations
* Contribute code improvements
* Help with documentation
* Share the plugin with others

**Development:**
* GitHub Repository: https://github.com/sadewadee/morden-security
* Coding Standards: WordPress Coding Standards
* Testing: PHPUnit and WordPress testing framework

== Credits ==

**Special Thanks:**
* WordPress community for security best practices
* Cloudflare for Turnstile technology
* Security researchers for vulnerability disclosure
* Beta testers and early adopters

**Third-Party Libraries:**
* None - Pure WordPress implementation

== Technical Requirements ==

**Minimum Requirements:**
* WordPress 6.1 or higher
* PHP 7.4 or higher
* MySQL 5.6 or higher
* 64MB PHP memory limit (128MB recommended)

**Recommended Environment:**
* WordPress 6.7+
* PHP 8.1+
* MySQL 8.0+
* 256MB PHP memory limit
* SSL certificate installed

**Server Compatibility:**
* Apache with mod_rewrite
* Nginx with proper configuration
* Shared hosting compatible
* VPS and dedicated servers
* Cloud hosting platforms

== License ==

This plugin is licensed under the GPL v2 or later.

This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program; if not, write to the Free Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.