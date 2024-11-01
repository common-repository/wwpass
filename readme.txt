=== WWPass Two-factor Authentication ===
Contributors: v.korshunov
Tags: authentication, login, security, two-factor, wwpass, multi-factor, 2FA, two-factor, Clef, Clef Replacement
Requires at least: 2.8.6
Tested up to: 5.1.1
Stable tag: trunk
License: Apache 2.0 license
License URI: http://www.apache.org/licenses/LICENSE-2.0

WWPass Two-factor Authentication for WordPress.

== Description ==

Easy, fast and fun to use – just scan the QR code and you’re in.

= Requirements =

* [cURL][]

[cURL]: http://curl.haxx.se/

== Installation ==

1. Log in to your Wordpress admin area and click Plugins > Add New;
2. Search for "WWPass Authentication" using the "Search plugins..." field on the right;
3. Install and activate the WWPass Authentication plugin;
4. Go to https://manage.wwpass.com and follow the instructions to create a new developer account and register your website. Once your website is registered, you will receive a pair of "crt" and "key" files, which are used to identify your website to WWPass;
5. Create a new directory on your website for your "crt" and "key" files. This directory should be inaccessible from the web, but should be readable by PHP. The best option is to create a directory outside of the document root of your website (see https://manage.wwpass.com/help#faq for more details);
6. Log in to your Wordpress admin area and click Settings > WWPass. Enter absolute paths to your "crt" and "key" files into the appropriate configuration fields and click "Check and save settings";
7. Before your PassKey can be used for authentication, you should bind it to your Wordpress user account. Log in to your Wordpress using your existing username and password, click WWPass and scan the QR code with your PassKey App. To bind your hardware PassKey, connect it to your computer and click the Bind button. In the latter case, your computer should also have WWPass Security Pack installed;
8. The next time you log in to your website, scan the QR code displayed on the authentication page with your PassKey App, or connect your PassKey to your computer and click "Log In with WWPass PassKey";

== Screenshots ==

1. Login Form
2. WWPass Two-factor Authentication Settings
3. WWPass Authentication
