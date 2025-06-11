=== Morden Security ===
Contributors: mordenhost, sadewadee
Donate link: https://mordenhost.com/donate/
Tags: security, firewall, malware, brute force, login protection, file integrity, permissions, ip blocking, security headers, wordpress security
Requires at least: 6.1
Tested up to: 6.7.2
Requires PHP: 7.4
Stable tag: 1.5.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Comprehensive WordPress security plugin with advanced firewall protection, brute force defense, file integrity monitoring, and complete security hardening.

== Description ==

**Morden Security** is a comprehensive WordPress security plugin designed to protect your website from modern threats and vulnerabilities. With advanced firewall protection, intelligent threat detection, and comprehensive security hardening features, Morden Security provides enterprise-level security for WordPress websites of all sizes.

= 🛡️ Key Security Features =

* **Advanced Firewall Protection** - Modern generation firewall with comprehensive threat detection
* **Intelligent IP Whitelist Management** - Auto-detection of server, admin, and logged-in user IPs
* **Brute Force Protection** - Login attempt limiting with intelligent IP blocking
* **File Integrity Monitoring** - WordPress core file verification and malware detection
* **Security Headers** - Complete HTTP security headers implementation
* **File Permissions Checker** - Deep scanning and automatic permission fixing
* **Upload Security** - File upload scanning with content analysis
* **Bot Protection** - Advanced bot detection with extensive bad bot database

= 🔥 Advanced Firewall Engine =

Our advanced firewall engine provides protection against:

* SQL Injection attacks with modern evasion detection
* Cross-Site Scripting (XSS) with comprehensive pattern matching
* Directory Traversal and Local File Inclusion attacks
* Remote Code Execution and Command Injection
* Protocol Manipulation and Header Injection
* Zero-day exploits and advanced persistent threats
* Malicious file uploads and backdoor attempts

= 🎯 Smart Protection Features =

* **Automatic IP Whitelisting** - Protects admins and logged-in users from accidental blocking
* **Geolocation Support** - Country detection with multiple API fallbacks
* **Rate Limiting** - API and request rate limiting with temporary blocking
* **Custom Block Pages** - Branded security block pages with detailed information
* **Real-time Monitoring** - Live security dashboard with threat statistics
* **Comprehensive Logging** - Detailed security event logging with export capabilities

= 🚀 Performance Optimized =

* Lightweight and fast execution
* Minimal database queries
* Efficient caching mechanisms
* WordPress standards compliant
* Mobile-responsive admin interface

= 💼 Enterprise Features =

* **Database Security** - Database prefix changer for enhanced security
* **Hide Login URL** - Custom login URL to prevent brute force attacks
* **File Editor Protection** - Disable WordPress file editor
* **XML-RPC Protection** - Block XML-RPC attacks
* **Version Hiding** - Hide WordPress version information
* **Admin Bar Customization** - Hide admin elements from non-admins

= 🔧 Easy Management =

* Modern, intuitive admin interface
* One-click security hardening
* Automated security maintenance
* Export/import security settings
* Comprehensive security reports

== Installation ==

= Automatic Installation =

1. Log in to your WordPress admin panel
2. Go to Plugins → Add New
3. Search for "Morden Security"
4. Click "Install Now" and then "Activate"
5. Navigate to Morden Security in your admin menu
6. Configure your security settings

= Manual Installation =

1. Download the plugin zip file
2. Extract the files to your `/wp-content/plugins/morden-security/` directory
3. Activate the plugin through the 'Plugins' menu in WordPress
4. Navigate to Morden Security → Settings to configure

= After Installation =

1. **Review Dashboard** - Check your security status on the main dashboard
2. **Configure Firewall** - Enable advanced firewall protection
3. **Set IP Whitelist** - Add trusted IP addresses to prevent accidental blocking
4. **Run Security Scan** - Perform initial file integrity check
5. **Review Settings** - Customize security features according to your needs

== Frequently Asked Questions ==

= Will this plugin slow down my website? =

No, Morden Security is designed for optimal performance. The firewall engine is highly optimized and uses efficient caching mechanisms to minimize impact on your website's speed.

= Can I whitelist my IP address to prevent being blocked? =

Yes, Morden Security automatically detects and whitelists admin IPs, server IPs, and logged-in user IPs. You can also manually add IP addresses to the whitelist.

= What happens if I get locked out of my website? =

If you get locked out, you can access your website via FTP and temporarily rename the plugin folder to disable it. We also provide emergency access methods in our documentation.

= Does this work with other security plugins? =

Morden Security is designed to work alongside other security plugins, but we recommend testing in a staging environment first. Some features may overlap with other security plugins.

= Can I customize the firewall rules? =

The firewall comes with comprehensive built-in rules that protect against modern threats. Advanced users can customize certain aspects through the settings panel.

= Is this plugin compatible with hosting providers like Cloudflare? =

Yes, Morden Security works seamlessly with CDNs and hosting providers. It automatically detects CloudFlare and other proxy services for accurate IP detection.

= How often should I run security scans? =

File integrity checks run automatically twice daily. You can also run manual scans anytime from the dashboard. We recommend weekly full security reviews.

= What should I do if malware is detected? =

If malware is detected, the plugin provides detailed instructions for manual cleanup. We recommend creating a backup before making any changes and consider professional security services for complex infections.

== Screenshots ==

1. **Security Dashboard** - Comprehensive overview of your website's security status with real-time statistics
2. **Firewall Settings** - Advanced firewall configuration with easy toggle switches
3. **Security Logs** - Detailed security event logging with filtering and export options
4. **Blocked IPs Management** - View and manage blocked IP addresses with country detection
5. **File Integrity Check** - WordPress core file verification with detailed reports
6. **IP Whitelist Management** - Comprehensive IP whitelist configuration
7. **File Permissions Checker** - Scan and fix insecure file permissions
8. **Security Settings** - Complete security hardening options

== Changelog ==

= 1.5.0 - 2025-01-12 =

**Major Release - Comprehensive Security Enhancement**

**🆕 New Features:**
* Advanced Firewall Protection (modern generation firewall engine)
* Comprehensive IP Whitelist Management with auto-detection
* File Permissions Checker with deep scanning capabilities
* WordPress Integrity Checker with malware detection
* Rate Limiter for API and login protection
* Enhanced Admin Interface with modern design
* Namespace support (MordenSecurity) for future development
* Auto-admin IP whitelisting on login
* File upload security scanning with content analysis
* POST data analysis for advanced threat detection
* Enhanced bot protection with extensive bad bot database
* Geolocation support with multiple API fallbacks
* Custom block pages with branded design

**🔒 Security Enhancements:**
* Enhanced SQL injection protection patterns
* Advanced XSS prevention with modern evasion technique detection
* Directory traversal protection improvements
* File inclusion vulnerability patches
* Code injection prevention enhancements
* Protocol manipulation blocking
* Header injection protection
* Null byte injection prevention
* Advanced encoding detection and blocking
* Zero-day exploit protection patterns

**🐛 Bug Fixes:**
* Fixed class loading issues and missing file dependencies
* Resolved endless loading states in admin pages
* Fixed file permission checker not working properly
* Corrected database table creation errors on activation
* Improved AJAX nonce verification and error handling
* Fixed CSS styling inconsistencies across admin pages
* Resolved memory leaks in firewall processing
* Fixed timezone issues in logging system
* Corrected plugin activation errors on various hosting environments
* Improved compatibility with other security plugins

**⚡ Performance Improvements:**
* Optimized firewall processing with better pattern matching
* Enhanced caching mechanisms for improved speed
* Better memory management and reduced resource usage
* Reduced database queries with efficient data retrieval
* Improved mobile responsive design for all admin pages

= 1.4.0 - 2024-12-15 =
* Enhanced login protection with IP tracking
* Improved security headers implementation
* Better WordPress core file protection
* Performance optimizations and bug fixes

= 1.3.0 - 2024-11-20 =
* Added basic firewall protection
* Implemented login attempt limiting
* Introduced security logging system

= 1.2.0 - 2024-10-15 =
* Added security headers functionality
* Implemented file editor protection
* Added XML-RPC blocking capability

= 1.1.0 - 2024-09-10 =
* Enhanced admin interface
* Added settings management
* Improved basic security features

= 1.0.0 - 2024-08-01 =
* Initial release
* Core security framework
* Basic protection features

== Upgrade Notice ==

= 1.5.0 =
Major security enhancement release! This version includes advanced firewall protection, comprehensive IP whitelist management, file integrity checking, and many security improvements. Backup recommended before upgrading. All existing settings will be preserved.

= 1.4.0 =
Important security updates and performance improvements. Recommended for all users.

= 1.3.0 =
Added firewall protection and login security features. Upgrade recommended.

== Additional Information ==

= Support =

For support, documentation, and feature requests, please visit:
* **Documentation**: https://mordenhost.com/docs/morden-security/
* **Support Forum**: https://wordpress.org/support/plugin/morden-security/
* **GitHub Repository**: https://github.com/sadewadee/morden-security/

= Contributing =

We welcome contributions! Please visit our GitHub repository to contribute code, report bugs, or suggest features.

= Privacy Policy =

Morden Security respects your privacy:
* No data is sent to external servers except for optional geolocation services
* All security logs are stored locally on your server
* IP geolocation uses public APIs (ip-api.com, ipapi.co) when enabled
* No personal information is collected or transmitted

= System Requirements =

* **WordPress**: 6.1 or higher
* **PHP**: 7.4 or higher (8.0+ recommended)
* **MySQL**: 5.7 or higher
* **Memory**: 128MB minimum (256MB recommended)
* **Disk Space**: 10MB for plugin files and logs

= Hosting Compatibility =

Tested and compatible with:
* Shared hosting environments
* VPS and dedicated servers
* WordPress.com Business plans
* Major hosting providers (SiteGround, Bluehost, WP Engine, etc.)
* CloudFlare and other CDN services

= Professional Services =

Need professional security services? Mordenhost offers:
* Security audits and hardening
* Malware removal services
* Custom security implementations
* 24/7 security monitoring

Contact us at: support@mordenhost.com
