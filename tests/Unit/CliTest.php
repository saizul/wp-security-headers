<?php
declare(strict_types=1);

namespace Saizul\SecurityHeaders\Tests\Unit;

use Saizul\SecurityHeaders\Cli\Command;
use Saizul\SecurityHeaders\Plugin;
use Saizul\SecurityHeaders\Settings;
use Saizul\SecurityHeaders\Tests\WpTestCase;
use WP_CLI;
use WpCliHalt;
use WpStubs;

final class CliTest extends WpTestCase {

	private static function command(): Command {
		return new Command( new Plugin( __FILE__ ) );
	}

	/**
	 * @return string[]
	 */
	private static function messages( string $type ): array {
		$out = array();
		foreach ( WP_CLI::$log as $entry ) {
			if ( $type === $entry[0] ) {
				$out[] = $entry[1];
			}
		}
		return $out;
	}

	public function test_status_table(): void {
		self::command()->status( array(), array() );
		$this->assertSame( array( 'header', 'value' ), WP_CLI::$items['fields'] );
		$this->assertSame( 'X-Content-Type-Options', WP_CLI::$items['items'][0]['header'] );
		$this->assertSame( array(), self::messages( 'warning' ) );
	}

	public function test_status_json_with_warnings(): void {
		WpStubs::$registry['home'] = 'http://example.org';
		self::store(
			array(
				'hsts_enabled'   => true,
				'csp_mode'       => Settings::CSP_REPORT_ONLY,
				'csp_directives' => array( 'script-src' => array( "'self'", "'unsafe-inline'" ) ),
			)
		);
		self::command()->status( array(), array( 'format' => 'json' ) );
		$data = json_decode( self::messages( 'line' )[0], true );
		$this->assertFalse( $data['https'] );
		$this->assertSame( 'report-only', $data['csp_mode'] );
		$names = array_column( $data['headers'], 'name' );
		$this->assertContains( 'Content-Security-Policy-Report-Only', $names );
		$this->assertNotContains( 'Strict-Transport-Security', $names );
		$text = implode( "\n", $data['warnings'] );
		$this->assertStringContainsString( 'HSTS: ', $text );
		$this->assertStringContainsString( "CSP: script-src allows 'unsafe-inline'", $text );
	}

	public function test_status_for_admin_area_that_is_off(): void {
		self::command()->status( array(), array( 'area' => 'admin' ) );
		$this->assertSame( array( 'No headers are sent for this area.' ), self::messages( 'warning' ) );
	}

	public function test_status_rejects_unknown_area(): void {
		$this->expectException( WpCliHalt::class );
		self::command()->status( array(), array( 'area' => 'api' ) );
	}

	public function test_scan_table_and_fail_under(): void {
		WpStubs::$responses[] = ScannerExportTest::response( 200, array( 'X-Content-Type-Options' => 'nosniff' ) );
		try {
			self::command()->scan( array(), array( 'fail-under' => 'C' ) );
			$this->fail( 'Expected exit status 1.' );
		} catch ( WpCliHalt $halt ) {
			$this->assertSame( 1, $halt->getCode() );
		}
		$this->assertSame( array( 'header', 'result', 'points', 'fix' ), WP_CLI::$items['fields'] );
		$this->assertStringStartsWith( 'Grade F (15/100) for https://example.org/', self::messages( 'line' )[0] );
		$this->assertNotNull( get_option( 'wp_security_headers_last_scan', null ) );
	}

	public function test_scan_json_for_a_url_passes_threshold(): void {
		WpStubs::$responses[] = ScannerExportTest::response(
			200,
			array(
				'Strict-Transport-Security'    => 'max-age=63072000',
				'Content-Security-Policy'      => "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'",
				'X-Content-Type-Options'       => 'nosniff',
				'Referrer-Policy'              => 'no-referrer',
				'Permissions-Policy'           => 'camera=()',
			)
		);
		self::command()->scan( array(), array( 'url' => 'https://example.org/shop/', 'format' => 'json', 'fail-under' => 'b' ) );
		$data = json_decode( self::messages( 'line' )[0], true );
		$this->assertSame( 'A', $data['grade'] );
		$this->assertSame( 90, $data['score'] );
		$this->assertSame( 'https://example.org/shop/', WpStubs::$requests[0]['url'] );
		$this->assertNull( get_option( 'wp_security_headers_last_scan', null ), 'scans of other URLs are not stored' );
	}

	public function test_scan_error(): void {
		$this->expectException( WpCliHalt::class );
		self::command()->scan( array(), array() );
	}

	public function test_scan_rejects_unknown_threshold(): void {
		WpStubs::$responses[] = ScannerExportTest::response( 200, array() );
		$this->expectException( WpCliHalt::class );
		$this->expectExceptionMessage( 'Unknown grade' );
		self::command()->scan( array(), array( 'fail-under' => 'Z' ) );
	}

	public function test_export(): void {
		self::command()->export( array(), array( 'server' => 'apache' ) );
		$this->assertStringContainsString( 'Header always set X-Content-Type-Options "nosniff"', self::messages( 'line' )[0] );
		WP_CLI::reset();
		self::command()->export( array(), array() );
		$this->assertStringContainsString( 'add_header X-Content-Type-Options "nosniff" always;', self::messages( 'line' )[0] );
		$this->expectException( WpCliHalt::class );
		self::command()->export( array(), array( 'server' => 'iis' ) );
	}
}
