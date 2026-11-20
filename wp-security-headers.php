<?php
/**
 * Plugin Name:       Security Headers
 * Plugin URI:        https://github.com/saizul/wp-security-headers
 * Description:       Add and test HTTP security headers without editing server config: HSTS, CSP builder with nonces and Report-Only reporting, Permissions-Policy, framing and cross-origin headers, an A-F scan and nginx/Apache export.
 * Version:           0.1.0
 * Requires at least: 6.3
 * Requires PHP:      7.4
 * Author:            Saizul Amin
 * Author URI:        https://saizul.com
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       wp-security-headers
 * Domain Path:       /languages
 *
 * @package Saizul\SecurityHeaders
 */

defined( 'ABSPATH' ) || exit;

if ( PHP_VERSION_ID < 70400 ) {
	add_action(
		'admin_notices',
		static function () {
			if ( current_user_can( 'activate_plugins' ) ) {
				echo '<div class="notice notice-error"><p>' . esc_html__( 'Security Headers requires PHP 7.4 or newer.', 'wp-security-headers' ) . '</p></div>';
			}
		}
	);
	return;
}

define( 'WP_SECURITY_HEADERS_FILE', __FILE__ );
define( 'WP_SECURITY_HEADERS_VERSION', '0.1.0' );

if ( is_readable( __DIR__ . '/vendor/autoload.php' ) ) {
	require_once __DIR__ . '/vendor/autoload.php';
} else {
	// PSR-4 autoloader for installs without Composer (the release zip).
	spl_autoload_register(
		static function ( $class_name ) {
			$prefix = 'Saizul\\SecurityHeaders\\';
			if ( 0 !== strncmp( $class_name, $prefix, strlen( $prefix ) ) ) {
				return;
			}
			$file = __DIR__ . '/src/' . str_replace( '\\', '/', substr( $class_name, strlen( $prefix ) ) ) . '.php';
			if ( is_readable( $file ) ) {
				require_once $file;
			}
		}
	);
}

register_activation_hook( __FILE__, array( \Saizul\SecurityHeaders\Plugin::class, 'activate' ) );

\Saizul\SecurityHeaders\Plugin::boot( __FILE__ );
