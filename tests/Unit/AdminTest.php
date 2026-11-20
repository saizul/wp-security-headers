<?php
declare(strict_types=1);

namespace Saizul\SecurityHeaders\Tests\Unit;

use Saizul\SecurityHeaders\Admin\SettingsPage;
use Saizul\SecurityHeaders\Admin\Tools;
use Saizul\SecurityHeaders\Plugin;
use Saizul\SecurityHeaders\Scanner;
use Saizul\SecurityHeaders\Settings;
use Saizul\SecurityHeaders\Tests\WpTestCase;
use WpDie;
use WpStubs;

final class AdminTest extends WpTestCase {

	protected function setUp(): void {
		parent::setUp();
		add_filter( 'security_headers_exit_after_redirect', '__return_false' );
	}

	private static function render( string $tab = 'settings' ): string {
		$_GET['tab'] = $tab;
		ob_start();
		( new SettingsPage( new Plugin( __FILE__ ) ) )->render();
		return (string) ob_get_clean();
	}

	public function test_register_settings_uses_the_sanitiser(): void {
		$page = new SettingsPage( new Plugin( __FILE__ ) );
		$page->register();
		$page->register_settings();
		$this->assertSame( array( Settings::class, 'sanitize' ), WpStubs::$registry['settings'][ Settings::OPTION ]['sanitize_callback'] );
		$this->assertNotFalse( has_filter( 'option_page_capability_' . SettingsPage::GROUP ) );
		$page->add_page();
		$this->assertSame( array( SettingsPage::SLUG ), WpStubs::calls( 'options_page' ) );
	}

	public function test_settings_tab_renders_every_section(): void {
		$html = self::render();
		$this->assertStringContainsString( 'action="options.php"', $html );
		$this->assertStringContainsString( 'name="option_page" value="wp_security_headers"', $html );
		$this->assertStringContainsString( 'name="wp_security_headers_settings[hsts_enabled]"', $html );
		$this->assertStringContainsString( 'name="wp_security_headers_settings[permissions][camera][on]"', $html );
		$this->assertStringContainsString( 'name="wp_security_headers_settings[csp_directives][script-src]"', $html );
		$this->assertStringContainsString( 'name="wp_security_headers_settings[apply_preset]"', $html );
		$this->assertStringContainsString( 'nav-tab-active', $html );
		$this->assertStringContainsString( 'default-src &#039;self&#039;', $html, 'policy preview is escaped' );
	}

	public function test_settings_tab_escapes_stored_values(): void {
		self::store( array( 'frame_ancestors' => array( '</textarea><script>alert(1)</script>' ) ) );
		$html = self::render();
		$this->assertStringNotContainsString( '<script>alert(1)</script>', $html );
	}

	public function test_render_requires_capability(): void {
		WpStubs::$can = false;
		$this->assertSame( '', self::render() );
		$this->assertSame( '', self::render( 'violations' ) );
	}

	public function test_unknown_tab_falls_back_to_settings(): void {
		$_GET['tab'] = '../../etc';
		$this->assertSame( 'settings', SettingsPage::current_tab() );
	}

	public function test_scan_tab_shows_last_result(): void {
		$this->assertStringContainsString( 'Scan my site', self::render( 'scan' ) );

		WpStubs::$responses[] = ScannerExportTest::response( 200, array( 'X-Powered-By' => '<b>PHP/8.3</b>' ) );
		( new Scanner() )->scan_and_store();
		$html = self::render( 'scan' );
		$this->assertStringContainsString( 'Grade', $html );
		$this->assertStringContainsString( 'Fix:', $html );
		$this->assertStringContainsString( '&lt;b&gt;PHP/8.3&lt;/b&gt;', $html );
		$this->assertStringNotContainsString( '<b>PHP/8.3</b>', $html );
	}

	public function test_scan_handler_checks_capability_and_nonce(): void {
		WpStubs::$can = false;
		try {
			( new Tools( new Plugin( __FILE__ ) ) )->handle_scan();
			$this->fail( 'Expected wp_die.' );
		} catch ( WpDie $e ) {
			$this->assertSame( array(), WpStubs::$requests );
		}

		WpStubs::$can      = true;
		WpStubs::$nonce_ok = false;
		try {
			( new Tools( new Plugin( __FILE__ ) ) )->handle_scan();
			$this->fail( 'Expected nonce failure.' );
		} catch ( WpDie $e ) {
			$this->assertSame( array( Tools::SCAN ), WpStubs::calls( 'check_admin_referer' ) );
			$this->assertSame( array(), WpStubs::$requests );
		}
	}

	public function test_scan_handler_stores_result_or_error(): void {
		WpStubs::$responses[] = ScannerExportTest::response( 200, array() );
		( new Tools( new Plugin( __FILE__ ) ) )->handle_scan();
		$this->assertStringContainsString( 'tab=scan', WpStubs::$redirect );
		$this->assertNotNull( Scanner::last() );

		( new Tools( new Plugin( __FILE__ ) ) )->handle_scan();
		$html = self::render( 'scan' );
		$this->assertStringContainsString( 'notice-error', $html );
		$this->assertStringNotContainsString( 'notice-error', self::render( 'scan' ), 'the error is shown once' );
	}

	public function test_violations_tab(): void {
		$this->assertStringContainsString( 'Reports arrive while', self::render( 'violations' ) );

		self::store( array( 'csp_mode' => Settings::CSP_REPORT_ONLY ) );
		$GLOBALS['wpdb']->var     = 1;
		$GLOBALS['wpdb']->results = array(
			array(
				'directive'    => 'script-src-elem',
				'blocked_uri'  => 'https://cdn.example.com/x.js',
				'document_uri' => 'https://example.org/',
				'source_file'  => '',
				'line_number'  => 0,
				'sample'       => '<img src=x onerror=alert(1)>',
				'disposition'  => 'report',
				'hits'         => 7,
				'first_seen'   => '2026-11-01 10:00:00',
				'last_seen'    => '2026-11-02 10:00:00',
			),
		);
		$html = self::render( 'violations' );
		$this->assertStringNotContainsString( 'Reports arrive while', $html );
		$this->assertStringContainsString( '1 distinct violation stored', $html );
		$this->assertStringContainsString( 'add it to script-src', $html );
		$this->assertStringContainsString( 'Delete all stored violations', $html );
		$this->assertStringNotContainsString( '<img src=x', $html );
	}

	public function test_clear_handler(): void {
		WpStubs::$nonce_ok = false;
		try {
			( new Tools( new Plugin( __FILE__ ) ) )->handle_clear();
			$this->fail( 'Expected nonce failure.' );
		} catch ( WpDie $e ) {
			$this->assertSame( array(), $GLOBALS['wpdb']->queries );
		}
		WpStubs::$nonce_ok = true;
		( new Tools( new Plugin( __FILE__ ) ) )->handle_clear();
		$this->assertSame( array( 'DELETE FROM `wp_security_headers_reports`' ), $GLOBALS['wpdb']->queries );
		$this->assertStringContainsString( 'tab=violations', WpStubs::$redirect );
	}

	public function test_export_tab(): void {
		$html = self::render( 'export' );
		$this->assertStringContainsString( 'add_header X-Content-Type-Options &quot;nosniff&quot; always;', $html );
		$this->assertStringContainsString( 'Header always set', $html );
	}

	public function test_action_links(): void {
		$links = ( new SettingsPage( new Plugin( __FILE__ ) ) )->action_links( array( 'deactivate' ) );
		$this->assertStringContainsString( 'page=wp-security-headers', $links[0] );
		WpStubs::$can = false;
		$this->assertSame( array( 'x' ), ( new SettingsPage( new Plugin( __FILE__ ) ) )->action_links( array( 'x' ) ) );
	}
}
