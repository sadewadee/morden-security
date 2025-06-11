=== Morden Security ===
Contributors: mordenhost
Tags: security, firewall, brute force, login protection, security headers, cloudflare turnstile, malware protection, ip blocking, wordpress security, bot protection, file integrity, hide login, database prefix, file permissions
Requires at least: 6.1
Tested up to: 6.7.2
Requires PHP: 7.4
Stable tag: 1.3.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Comprehensive WordPress security plugin with Hide Login URL, Database Prefix Changer, File Permission Checker, plus advanced protection features.

== Description ==

**Morden Security** is a comprehensive WordPress security plugin designed to protect your website from various online threats and attacks. Version 1.3.0 introduces three critical security enhancements that significantly improve your website's security posture.

= 🆕 NEW in v1.3.0 - Critical Security Enhancements =

**Hide Login URL:**
* Custom login page URL to hide wp-admin and wp-login.php from bots
* Configurable custom path (e.g., yoursite.com/secure-login)
* Automatic redirection of default login attempts to 404
* Prevents brute force attacks by obscuring login page

**Database Prefix Changer:**
* Change default "wp_" database prefix to custom secure prefix
* Automatic backup creation before prefix change
* Updates all database tables and wp-config.php automatically
* Prevents SQL injection attacks targeting default table names

**File Permission Checker:**
* Comprehensive scan of WordPress file and folder permissions
* Identifies insecure permissions (777, 666) that pose security risks
* One-click fix for common permission issues
* Detailed reporting with recommended vs current permissions

= 🛡️ Core Security Features =

**Basic Security Protection:**
* Disable WordPress file editor for themes and plugins
* Force HTTPS connections across your site
* Disable XML-RPC to prevent brute force attacks
* Add essential security headers automatically
* Block PHP execution in wp-content/uploads directory
* Disable pingbacks and trackbacks completely
* Advanced bot protection and user agent filtering
* Block author enumeration via author archives

**File Scanning & Integrity Check:**
* WordPress core file integrity monitoring with official checksums
* Real-time malware detection with signature-based scanning
* Plugin and theme security scanning
* Manual repair instructions for infected files
* Configurable scan sensitivity levels
* Custom folder exclusions for false positive reduction

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

**Security Monitoring:**
* Comprehensive security logs with country tracking
* One-click IP blocking directly from security logs
* Export security logs to CSV
* Real-time security statistics dashboard
* Configurable log retention (1-365 days, 100-10000 entries)

== Installation ==

= Automatic Installation =

1. Log in to your WordPress admin panel
2. Navigate to Plugins → Add New
3. Search for "Morden Security"
4. Click "Install Now" and then "Activate"
5. Go to Morden Security in admin menu to configure

= Manual Installation =

1. Download the plugin ZIP file
2. Upload the `morden-security` folder to `/wp-content/plugins/`
3. Activate the plugin through the 'Plugins' menu in WordPress
4. Configure the plugin at Morden Security → Settings

= Configuration =

1. **Basic Security**: Enable core security features including new security enhancements
2. **Login Protection**: Configure brute force protection
3. **Firewall**: Set up advanced threat protection
4. **File Scanning & Integrity**: Configure scanning and integrity monitoring
5. **Log Management**: Set retention policies and preferences

== Frequently Asked Questions ==

= What's new in v1.3.0? =

Version 1.3.0 introduces three critical security enhancements:
- **Hide Login URL**: Custom login page URL to prevent bot attacks
- **Database Prefix Changer**: Change default "wp_" prefix for better security
- **File Permission Checker**: Scan and fix insecure file permissions

= Is it safe to change the database prefix? =

Yes, but always create a backup first. Our tool automatically creates a backup before making changes and updates all necessary files including wp-config.php.

= What happens if I forget my custom login URL? =

You can access your site via FTP and temporarily rename the plugin folder to restore default login access, or check your plugin settings in the database.

= Will this plugin slow down my website? =

No, Morden Security is designed to be lightweight and efficient. Most security features work at the server level and don't impact page load times.

= Can I use this with other security plugins? =

While it's technically possible, we recommend using only one comprehensive security plugin to avoid conflicts and redundancy.

== Screenshots ==

1. **Main Security Dashboard** - Overview with real-time statistics and new security features
2. **Enhanced Basic Security Settings** - New features: Hide Login URL, Database Prefix, File Permissions
3. **Database Prefix Changer** - Secure database prefix modification with backup
4. **File Permission Checker** - Comprehensive permission scanning and fixing
5. **Hide Login URL Configuration** - Custom login page URL setup
6. **File Scanning & Integrity** - WordPress core integrity monitoring with manual repair guide
7. **Security Logs with Actions** - Detailed logging with one-click IP blocking

== Changelog ==

= 1.3.0 - 2025-06-11 =
**Critical Security Enhancements - Major Feature Update**

**NEW Security Features:**
* **Hide Login URL** - Custom login page URL with configurable path
* **Database Prefix Changer** - Secure database prefix modification with automatic backup
* **File Permission Checker** - Comprehensive permission scanning and one-click fixing

**Security Enhancements:**
* Enhanced login URL protection with 404 redirection for default paths
* Automatic database backup creation before critical changes
* Detailed file permission analysis with security recommendations
* Improved bot protection with custom login URL obscurity

**User Interface Improvements:**
* Updated admin interface with new security feature integration
* Real-time login URL preview in settings
* Visual security status indicators for database and file permissions
* Enhanced AJAX functionality for seamless user experience

**Performance & Reliability:**
* Optimized database operations for prefix changes
* Improved error handling and validation
* Enhanced backup and recovery mechanisms
* Better compatibility with various hosting environments

= 1.2.1-beta - 2025-06-09 =
**Enhanced File Scanning & Integrity Check**

**New Security Features:**
* Block PHP in Uploads - Prevent PHP execution in uploads directory
* Disable Pingbacks - Complete pingback and trackback protection
* Bot Protection - Advanced bot detection with user agent filtering
* Block Author Scans - Prevent username enumeration
* File Integrity Checker - Monitor WordPress core files

**Security Logs Enhancements:**
* Added "Block IP" action button in security logs
* One-click IP blocking with custom reason input
* Enhanced security logs with country and path tracking

= 1.2.0-beta - 2025-06-07 =
**Initial Beta Release**

**Core Security Features:**
* Basic WordPress security hardening
* Brute force protection with IP blocking
* Advanced firewall with pattern detection
* Security headers implementation
* Cloudflare Turnstile integration

== Upgrade Notice ==

= 1.3.0 =
Major security enhancement! New features include Hide Login URL, Database Prefix Changer, and File Permission Checker. These critical security improvements significantly enhance your website's protection. Recommended upgrade for all users.

= 1.2.1-beta =
Enhanced file scanning and integrity monitoring with one-click IP blocking from security logs. Recommended upgrade for improved security monitoring.

== Support ==

**GitHub Repository:** https://github.com/sadewadee/morden-security

**Support & Bug Reports:** https://github.com/sadewadee/morden-security/issues

**Contact:** support@mordenhost.com

== License ==

This plugin is licensed under the GPL v2 or later.