<?php
declare(strict_types=1);

namespace Saizul\SecurityHeaders\Tests\Unit;

use Saizul\SecurityHeaders\Frontend;
use Saizul\SecurityHeaders\Nonce;
use Saizul\SecurityHeaders\Plugin;
use Saizul\SecurityHeaders\Settings;
use Saizul\SecurityHeaders\Tests\WpTestCase;
use WP_CLI;
use WpStubs;

final class FrontendTest extends WpTestCase {

	/** @var string[] */
	private $sent = array();

	/** @var string[] */
	private $removed = array();

	private function frontend( bool $already_sent = false ): Frontend {
		return new Frontend(
			new Plugin( __FILE__ ),
			function ( string $line ): void {
				$this->sent[] = $line;
			},
			function ( string $name ): void {
				$this->removed[] = $name;
			},
			static function () use ( $already_sent ): bool {
				return $already_sent;
			}
		);
	}

	public function test_send_emits_every_header_and_removes_powered_by(): void {
		$count = $this->frontend()->send( 'front' );
		$this->assertSame( 5, $count );
		$this->assertSame( 'X-Content-Type-Options: nosniff', $this->sent[0] );
		$this->assertSame( array( 'X-Powered-By' ), $this->removed );
	}

	public function test_nothing_is_sent_after_output_started(): void {
		$this->assertSame( 0, $this->frontend( true )->send( 'front' ) );
		$this->assertSame( array(), $this->sent );
	}

	public function test_keep_powered_by_when_switched_off(): void {
		self::store( array( 'remove_powered_by' => false ) );
		$this->frontend()->send( 'front' );
		$this->assertSame( array(), $this->removed );
	}

	public function test_hooks_follow_the_settings(): void {
		$this->frontend()->register();
		$this->assertNotFalse( has_filter( 'send_headers' ) );
		$this->assertFalse( has_filter( 'admin_init' ) );
		$this->assertFalse( has_filter( 'login_init' ) );
		$this->assertFalse( has_filter( 'wp_script_attributes' ) );

		WpStubs::reset();
		self::store(
			array(
				'apply_admin' => true,
				'apply_login' => true,
				'csp_mode'    => Settings::CSP_ENFORCE,
				'csp_nonce'   => true,
			)
		);
		$this->frontend()->register();
		$this->assertNotFalse( has_filter( 'admin_init' ) );
		$this->assertNotFalse( has_filter( 'login_init' ) );
		$this->assertNotFalse( has_filter( 'wp_script_attributes' ) );
		$this->assertNotFalse( has_filter( 'wp_inline_script_attributes' ) );
	}

	public function test_nonce_matches_header_and_script_tags(): void {
		WpStubs::$ssl = true;
		self::store(
			array(
				'csp_mode'  => Settings::CSP_ENFORCE,
				'csp_nonce' => true,
			)
		);
		$this->frontend()->register();
		$this->frontend()->send( 'front' );

		$attributes = apply_filters( 'wp_script_attributes', array( 'src' => '/app.js' ) );
		$inline     = apply_filters( 'wp_inline_script_attributes', array( 'id' => 'x-js-after' ), 'code' );
		$nonce      = $attributes['nonce'];
		$this->assertSame( $nonce, $inline['nonce'] );
		$this->assertSame( 1, preg_match( '#^[A-Za-z0-9+/]{22}==$#', $nonce ) );

		$csp = '';
		foreach ( $this->sent as $line ) {
			if ( 0 === strpos( $line, 'Content-Security-Policy: ' ) ) {
				$csp = $line;
			}
		}
		$this->assertStringContainsString( "'nonce-" . $nonce . "'", $csp );
		$this->assertSame( 'not-an-array', Nonce::add_attribute( 'not-an-array' ) );
	}

	public function test_nonce_changes_per_request(): void {
		$first = Nonce::value();
		$this->assertSame( $first, Nonce::value() );
		Nonce::reset();
		$this->assertNotSame( $first, Nonce::value() );
	}

	public function test_headers_filter_cannot_inject_lines(): void {
		add_filter(
			'security_headers_headers',
			static function ( $headers ) {
				$headers[] = array( 'X-Test', 'ok' );
				$headers[] = array( 'X-Evil', "a\r\nSet-Cookie: x=1" );
				$headers[] = array( 'Bad Name', 'x' );
				$headers[] = 'garbage';
				return $headers;
			}
		);
		$map = self::map( ( new Plugin( __FILE__ ) )->headers( 'front' ) );
		$this->assertSame( 'ok', $map['X-Test'] );
		$this->assertArrayNotHasKey( 'X-Evil', $map );
		$this->assertArrayNotHasKey( 'Bad Name', $map );
	}

	public function test_hsts_follows_is_ssl(): void {
		self::store( array( 'hsts_enabled' => true ) );
		$plugin = new Plugin( __FILE__ );
		$this->assertArrayNotHasKey( 'Strict-Transport-Security', self::map( $plugin->headers( 'front' ) ) );
		WpStubs::$ssl = true;
		$this->assertSame( 'max-age=31536000', self::map( $plugin->headers( 'front' ) )['Strict-Transport-Security'] );
	}

	public function test_boot_registers_everything(): void {
		WpStubs::$admin = true;
		Plugin::boot( __FILE__ );
		$this->assertSame( Plugin::instance(), Plugin::boot( __FILE__ ) );
		$this->assertNotFalse( has_filter( 'send_headers' ) );
		$this->assertNotFalse( has_filter( 'rest_api_init' ) );
		$this->assertNotFalse( has_filter( 'admin_menu' ) );
		$this->assertNotFalse( has_filter( 'admin_post_wp_security_headers_scan' ) );
		$this->assertNotFalse( has_filter( 'admin_post_wp_security_headers_clear' ) );
		$this->assertSame( array(), WP_CLI::$log );
	}

	public function test_init_loads_textdomain_and_installs_table_when_reporting(): void {
		$plugin = new Plugin( __FILE__ );
		$plugin->init();
		$this->assertSame( array( 'wp-security-headers' ), WpStubs::calls( 'load_plugin_textdomain' ) );
		$this->assertSame( array(), WpStubs::calls( 'dbDelta' ) );

		self::store( array( 'csp_mode' => Settings::CSP_REPORT_ONLY ) );
		$plugin->init();
		$this->assertCount( 1, WpStubs::calls( 'dbDelta' ) );
	}

	public function test_activation_creates_table(): void {
		Plugin::activate();
		$this->assertCount( 1, WpStubs::calls( 'dbDelta' ) );
	}

	public function test_capability_filter(): void {
		$this->assertSame( 'manage_options', Plugin::capability() );
		add_filter(
			'security_headers_capability',
			static function () {
				return '';
			}
		);
		$this->assertSame( 'manage_options', Plugin::capability() );
	}
}
