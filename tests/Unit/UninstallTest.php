<?php
declare(strict_types=1);

namespace Saizul\SecurityHeaders\Tests\Unit;

use Saizul\SecurityHeaders\Settings;
use Saizul\SecurityHeaders\Tests\WpTestCase;
use WpStubs;

/**
 * @runTestsInSeparateProcesses
 * @preserveGlobalState disabled
 */
final class UninstallTest extends WpTestCase {

	public function test_deletes_options_and_table(): void {
		WpStubs::$options[ Settings::OPTION ]               = array( 'nosniff' => true );
		WpStubs::$options['wp_security_headers_last_scan']  = array();
		WpStubs::$options['wp_security_headers_db_version'] = '1';
		WpStubs::$options['blogname']                       = 'Kept';
		define( 'WP_UNINSTALL_PLUGIN', 'wp-security-headers/wp-security-headers.php' );
		require dirname( __DIR__, 2 ) . '/uninstall.php';

		self::assertSame( array( 'blogname' => 'Kept' ), WpStubs::$options );
		self::assertSame( array( 'DROP TABLE IF EXISTS `wp_security_headers_reports`' ), $GLOBALS['wpdb']->queries );
	}

	public function test_cleans_every_site_of_a_network(): void {
		WpStubs::$registry['multisite']      = true;
		WpStubs::$registry['sites']          = array( 1, 2 );
		WpStubs::$registry['site_options:1'] = array( Settings::OPTION => array() );
		WpStubs::$registry['site_options:2'] = array(
			Settings::OPTION => array(),
			'other'          => 1,
		);
		define( 'WP_UNINSTALL_PLUGIN', 'wp-security-headers/wp-security-headers.php' );
		require dirname( __DIR__, 2 ) . '/uninstall.php';

		self::assertSame( array( '1', '2' ), WpStubs::calls( 'switch_to_blog' ) );
		self::assertSame( array(), WpStubs::$registry['site_options:1'] );
		self::assertSame( array( 'other' => 1 ), WpStubs::$registry['site_options:2'] );
		self::assertSame(
			array(
				'DROP TABLE IF EXISTS `wp_security_headers_reports`',
				'DROP TABLE IF EXISTS `wp_2_security_headers_reports`',
			),
			$GLOBALS['wpdb']->queries
		);
	}
}
