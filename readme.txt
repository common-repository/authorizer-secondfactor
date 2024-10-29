=== Authorizer SecondFactor ===
Tags: 2fa, auth, authenticate, authentication, login, otp, password, security, sms, tfa, two factor, two factor auth
Requires at least: 3.3
Tested up to: 5.3
Stable tag: 1.1.3
Requires PHP: 5.3
Author: Signatis GmbH
Contributors: Signatis GmbH and David Nutbourne and David Anderson and Oskar Hane
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Secure your WordPress login with Two Factor Authentication based on *Authorizer SecondFactor*. For more information see: <a href="https://www.authorizer.de/en/wordpress" target="_blank" rel="noopener noreferrer">www.authorizer.de/en/wordpress</a>

== Description ==

This plugin enables you to secure your WordPress login with two factor authentication (TFA / 2FA) based on *Authorizer SecondFactor*. Users for whom it is enabled will require an additional one-time code besides their password in order to log in.

For more information see <a href="https://www.authorizer.de/en/wordpress" target="_blank" rel="noopener noreferrer">www.authorizer.de/en/wordpress</a> and the "Screenshots" section below.

= Features =

* Plugin supports the Authorizer SecondFactor API
* Simplified and user friendly UI with overview of all users
* Two-factor settings can be turned on/off for each user individually
* One-time code can be sent by email or SMS (mailTAN or smsTAN/mTAN)
* Free version available
* Easy initial auto-configuration
* Supports latest WordPress version (5.3.1)
* WP Multisite compatible
* Backup of your SecondFactor data in the Authorizer Cloud
* Pro feature: Unlimited transactions in tariffs "Team" and "Business"
* Pro feature: Supports several WordPress instances in parallel (free for all tariffs)
* Pro feature: Sync of your SecondFactor data between multiple WordPress instances (free for all tariffs)

= How does it work? =

This plugin uses the *Authorizer SecondFactor* API (<a href="https://www.authorizer.de/en/wordpress" target="_blank" rel="noopener noreferrer">www.authorizer.de/en/wordpress</a>) to manage accounts and generate, send and validate challenges (OTP / TAN).

= Plugin notes =

This plugin is a fork of the Two Factor Authentication plugin by David Nutbourne and David Anderson, original plugin by Oskar Hane.

== Installation ==

This plugin requires PHP version 5.3 or higher and either php-openssl or [PHP mcrypt](http://www.php.net/manual/en/mcrypt.installation.php). The vast majority of PHP setups will have one of these. If not, ask your hosting company.

1. Search for 'Authorizer SecondFactor' in the 'Plugins' menu in WordPress.
2. Click the 'Install' button (make sure you pick the right one).
3. Activate the plugin through the 'Plugins' menu in WordPress.
4. Find site-wide settings in Settings -> Authorizer SecondFactor.
5. Let the plugin auto-configure itself by simply entering your Authorizer credentials.

== Screenshots ==

1. Initial plugin auto-configuration

2. Side-wide SecondFactor/TFA settings

3. Log-in step 1: Provide your password

4. Log-in step 2: Choose your additional OTP method

5. Log-in step 3: Enter OTP code

== Changelog ==

= 1.1.3 =
* Bugfix localization: Set "Text Domain" to "authorizer-secondfactor" and renamed language files accordingly.

= 1.1.2 =
* Corrected image paths for icons

= 1.1.1 =
* Bugfix for older WordPress versions that could cause JavaScript errors on login under certain conditions

= 1.1.0 =
* Implemented offline refresh tokens

= 1.0.5 =
* Bugfix for PHP versions < 7 that could cause loading the account list to fail under certain conditions

= 1.0.4 =
* Using WordPress-integrated methods for HTTP calls

= 1.0.3 =
* Update for WordPress 5.3
* Show amount of available sms and transactions

= 1.0.2 =
* Internal optimizations and performance improvements

= 1.0.1 =
* Layout optimizations of the TFA user overview
* Added German translations

= 1.0.0 =
* First stable version
