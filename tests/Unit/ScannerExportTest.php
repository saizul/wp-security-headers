<?php
declare(strict_types=1);

namespace Saizul\SecurityHeaders\Tests\Unit;

use Saizul\SecurityHeaders\Export;
use Saizul\SecurityHeaders\Scanner;
use Saizul\SecurityHeaders\Settings;
use Saizul\SecurityHeaders\Tests\WpTestCase;
use WP_Error;
use WpStubs;

final class ScannerExportTest extends WpTestCase {

	/**
	 * A stub HTTP API response.
	 *
	 * @param int                           $code    Status.
	 * @param array<string,string|string[]> $headers Headers.
	 * @return array<string,mixed>
	 */
	public static function response( int $code, array $headers ): array {
		return array(
			'response' => array( 'code' => $code ),
			'headers'  => $headers,
			'body'     => '<html></html>',
		);
	}

	public function test_scan_grades_the_home_page(): void {
		WpStubs::$responses[] = self::response(
			200,
			array(
				'X-Content-Type-Options' => 'nosniff',
				'X-Frame-Options'        => 'DENY',
			)
		);
		$result = ( new Scanner() )->scan();

		$this->assertSame( 'https://example.org/', WpStubs::$requests[0]['url'] );
		$this->assertSame( 0, WpStubs::$requests[0]['args']['redirection'] );
		$this->assertSame( 200, $result['status'] );
		$this->assertTrue( $result['https'] );
		$this->assertSame( array( 'nosniff' ), $result['headers']['x-content-type-options'] );
		$this->assertSame( 30, $result['result']['score'] );
		$this->assertSame( 'E', $result['result']['grade'] );
	}

	public function test_scan_follows_redirects(): void {
		WpStubs::$registry['home'] = 'http://example.org';
		WpStubs::$responses[]      = self::response( 301, array( 'Location' => 'https://example.org/' ) );
		WpStubs::$responses[]      = self::response( 302, array( 'location' => '/en/' ) );
		WpStubs::$responses[]      = self::response( 200, array( 'Strict-Transport-Security' => 'max-age=63072000' ) );
		$result                    = ( new Scanner() )->scan();

		$this->assertSame( 'https://example.org/en/', $result['url'] );
		$this->assertSame( array( 'http://example.org/', 'https://example.org/' ), $result['redirects'] );
		$this->assertTrue( $result['https'] );
		$this->assertSame( 20, $result['result']['findings'][1]['score'] );
	}

	public function test_scan_gives_up_after_too_many_redirects(): void {
		for ( $i = 0; $i < 5; $i++ ) {
			WpStubs::$responses[] = self::response( 302, array( 'Location' => '/loop' ) );
		}
		$result = ( new Scanner() )->scan();
		$this->assertInstanceOf( WP_Error::class, $result );
		$this->assertSame( 'security_headers_too_many_redirects', $result->get_error_code() );
		$this->assertCount( Scanner::MAX_REDIRECTS + 1, WpStubs::$requests );
	}

	public function test_scan_errors(): void {
		$failed = ( new Scanner() )->scan();
		$this->assertInstanceOf( WP_Error::class, $failed );
		$this->assertStringContainsString( 'Loopback', $failed->get_error_message() );

		WpStubs::$requests = array();
		$bad               = ( new Scanner() )->scan( 'file:///etc/passwd' );
		$this->assertSame( 'security_headers_bad_url', $bad->get_error_code() );
		$this->assertSame( array(), WpStubs::$requests );
	}

	public function test_scan_and_store_remembers_the_last_result(): void {
		$this->assertNull( Scanner::last() );
		WpStubs::$responses[] = self::response( 200, array() );
		( new Scanner() )->scan_and_store();
		$this->assertSame( 'F', Scanner::last()['result']['grade'] );

		( new Scanner() )->scan_and_store();
		$this->assertSame( 'F', Scanner::last()['result']['grade'], 'a failed scan keeps the previous result' );
	}

	public function test_headers_from_requests_dictionary(): void {
		$dictionary = new class() {
			/** @return array<string,string[]> */
			public function getAll(): array {
				return array( 'Content-Security-Policy' => array( "frame-ancestors 'self'", "default-src 'self'" ) );
			}
		};
		$headers    = Scanner::headers( array( 'headers' => $dictionary ) );
		$this->assertSame( array( 'content-security-policy' => array( "frame-ancestors 'self'", "default-src 'self'" ) ), $headers );
	}

	public function test_resolve_locations(): void {
		$this->assertSame( 'https://b.example/x', Scanner::resolve( 'https://a.example/', 'https://b.example/x' ) );
		$this->assertSame( 'http://cdn.example/y', Scanner::resolve( 'http://a.example/', '//cdn.example/y' ) );
		$this->assertSame( 'https://a.example:8443/z', Scanner::resolve( 'https://a.example:8443/q/r', '/z' ) );
		$this->assertSame( 'https://a.example/q/s', Scanner::resolve( 'https://a.example/q/r', 's' ) );
	}

	public function test_nginx_export(): void {
		$out = Export::nginx(
			array(
				array( 'X-Content-Type-Options', 'nosniff' ),
				array( 'Reporting-Endpoints', 'wpsh-csp="https://example.org/r"' ),
			),
			array( "Note with\nnewline" )
		);
		$this->assertStringContainsString( 'add_header X-Content-Type-Options "nosniff" always;', $out );
		$this->assertStringContainsString( 'add_header Reporting-Endpoints "wpsh-csp=\\"https://example.org/r\\"" always;', $out );
		$this->assertStringContainsString( '# Note with newline', $out );
		$this->assertStringContainsString( '# No headers are switched on.', Export::nginx( array() ) );
	}

	public function test_apache_export(): void {
		$out = Export::render( Export::APACHE, array( array( 'Referrer-Policy', 'no-referrer' ) ) );
		$this->assertStringContainsString( "<IfModule mod_headers.c>\n    Header always set Referrer-Policy \"no-referrer\"\n</IfModule>", $out );
		$this->assertSame( 'a \\"b\\" \\\\ c', Export::quote( "a \"b\" \\ c" ) );
	}

	public function test_export_uses_https_and_drops_the_nonce(): void {
		$settings = self::settings(
			array(
				'hsts_enabled' => true,
				'csp_mode'     => Settings::CSP_ENFORCE,
				'csp_nonce'    => true,
			)
		);
		$map      = self::map( Export::headers( $settings, 'https://example.org/wp-json/security-headers/v1/report' ) );
		$this->assertSame( 'max-age=31536000', $map['Strict-Transport-Security'] );
		$this->assertStringNotContainsString( 'nonce-', $map['Content-Security-Policy'] );
		$notes = implode( "\n", Export::notes( $settings ) );
		$this->assertStringContainsString( 'Nonces are left out', $notes );
		$this->assertStringContainsString( 'Strict-Transport-Security', $notes );
	}
}
