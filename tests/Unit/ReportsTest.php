<?php
declare(strict_types=1);

namespace Saizul\SecurityHeaders\Tests\Unit;

use Saizul\SecurityHeaders\Reports\Parser;
use Saizul\SecurityHeaders\Reports\RateLimiter;
use Saizul\SecurityHeaders\Reports\Store;
use Saizul\SecurityHeaders\Reports\Suggest;
use Saizul\SecurityHeaders\Tests\WpTestCase;
use FakeWpdb;
use WpStubs;

final class ReportsTest extends WpTestCase {

	/**
	 * A legacy report-uri body.
	 *
	 * @param array<string,mixed> $overrides Fields.
	 */
	public static function legacy( array $overrides = array() ): string {
		return (string) json_encode(
			array(
				'csp-report' => array_merge(
					array(
						'document-uri'        => 'https://example.org/shop/?session=secret#frag',
						'referrer'            => 'https://search.example/',
						'violated-directive'  => 'script-src-elem',
						'effective-directive' => 'script-src-elem',
						'original-policy'     => "default-src 'self'",
						'disposition'         => 'report',
						'blocked-uri'         => 'https://cdn.example.com/lib.js?v=3',
						'line-number'         => 12,
						'source-file'         => 'https://example.org/wp-content/themes/x/app.js?ver=1',
						'status-code'         => 200,
						'script-sample'       => '',
					),
					$overrides
				),
			)
		);
	}

	public function test_parse_legacy_report(): void {
		$out = Parser::parse( self::legacy(), 'application/csp-report' );
		$this->assertSame(
			array(
				array(
					'directive'   => 'script-src-elem',
					'blocked_uri' => 'https://cdn.example.com/lib.js',
					'document'    => 'https://example.org/shop/',
					'source_file' => 'https://example.org/wp-content/themes/x/app.js',
					'line'        => 12,
					'sample'      => '',
					'disposition' => 'report',
				),
			),
			$out
		);
	}

	public function test_violated_directive_fallback_takes_first_token(): void {
		$body = (string) json_encode(
			array(
				'csp-report' => array(
					'document-uri'       => 'https://example.org/',
					'violated-directive' => "style-src 'self'",
					'blocked-uri'        => 'inline',
				),
			)
		);
		$out = Parser::parse( $body, 'application/csp-report' );
		$this->assertSame( 'style-src', $out[0]['directive'] );
		$this->assertSame( 'inline', $out[0]['blocked_uri'] );
	}

	public function test_parse_reporting_api_batch(): void {
		$body = (string) json_encode(
			array(
				array(
					'type' => 'csp-violation',
					'age'  => 10,
					'url'  => 'https://example.org/',
					'body' => array(
						'documentURL'        => 'https://example.org/blog/',
						'blockedURL'         => 'eval',
						'effectiveDirective' => 'script-src',
						'disposition'        => 'enforce',
						'sample'             => "eval('1+1')\n",
						'lineNumber'         => '7',
					),
				),
				array(
					'type' => 'deprecation',
					'body' => array( 'id' => 'x' ),
				),
				array(
					'type' => 'csp-violation',
					'body' => array(
						'documentURL'        => 'https://example.org/',
						'blockedURL'         => 'data:image/png;base64,AAAA',
						'effectiveDirective' => 'img-src',
					),
				),
			)
		);
		$out = Parser::parse( $body, 'application/reports+json; charset=utf-8' );
		$this->assertCount( 2, $out );
		$this->assertSame( 'eval', $out[0]['blocked_uri'] );
		$this->assertSame( 'enforce', $out[0]['disposition'] );
		$this->assertSame( "eval('1+1')", $out[0]['sample'] );
		$this->assertSame( 7, $out[0]['line'] );
		$this->assertSame( 'data', $out[1]['blocked_uri'] );
		$this->assertSame( '', $out[1]['disposition'] );
	}

	/**
	 * @return array<string,array{0:string,1:string,2:int}>
	 */
	public function bad_bodies(): array {
		return array(
			'wrong content type' => array( self::legacy(), 'text/plain', 415 ),
			'form post'          => array( 'a=b', 'application/x-www-form-urlencoded', 415 ),
			'invalid json'       => array( '{nope', 'application/csp-report', 400 ),
			'json scalar'        => array( '"text"', 'application/json', 400 ),
			'no reports'         => array( '[]', 'application/reports+json', 400 ),
			'other report types' => array( '[{"type":"intervention","body":{}}]', 'application/reports+json', 400 ),
			'bad directive'      => array( self::legacy( array( 'effective-directive' => '<script>', 'violated-directive' => '' ) ), 'application/csp-report', 400 ),
			'no document'        => array( self::legacy( array( 'document-uri' => 'about:blank' ) ), 'application/csp-report', 400 ),
			'too large'          => array( str_repeat( ' ', Parser::MAX_BYTES + 1 ), 'application/json', 413 ),
		);
	}

	/**
	 * @dataProvider bad_bodies
	 */
	public function test_invalid_reports_are_rejected( string $body, string $type, int $status ): void {
		$error = Parser::parse( $body, $type );
		$this->assertInstanceOf( \WP_Error::class, $error );
		$this->assertSame( $status, $error->get_error_data()['status'] );
	}

	public function test_example_payloads_parse(): void {
		$dir    = dirname( __DIR__, 2 ) . '/examples/reports/';
		$legacy = Parser::parse( (string) file_get_contents( $dir . 'csp-report.json' ), 'application/csp-report' );
		$api    = Parser::parse( (string) file_get_contents( $dir . 'reports-api.json' ), 'application/reports+json' );
		$this->assertSame( 'https://cdn.example.net/widget.js', $legacy[0]['blocked_uri'] );
		$this->assertSame( 'inline', $api[0]['blocked_uri'] );
		$this->assertSame( 42, $api[0]['line'] );
	}

	public function test_batches_are_capped(): void {
		$item = array(
			'type' => 'csp-violation',
			'body' => array(
				'documentURL'        => 'https://example.org/',
				'blockedURL'         => 'inline',
				'effectiveDirective' => 'script-src-elem',
			),
		);
		$out = Parser::parse( (string) json_encode( array_fill( 0, 50, $item ) ), 'application/reports+json' );
		$this->assertCount( Parser::MAX_REPORTS, $out );
	}

	public function test_url_cleaning(): void {
		$this->assertSame( 'https://example.org:8443/a', Parser::url( 'HTTPS://user:pass@Example.ORG:8443/a?x=1#y' ) );
		$this->assertSame( '', Parser::url( 'javascript:alert(1)' ) );
		$this->assertSame( '', Parser::url( 'https://exa mple.org/' ) );
		$this->assertSame( '', Parser::url( 42 ) );
		$this->assertLessThanOrEqual( 512, strlen( Parser::url( 'https://example.org/' . str_repeat( 'a', 2000 ) ) ) );
		$this->assertSame( 'blob', Parser::blocked( 'blob:https://example.org/uuid' ) );
		$this->assertSame( 'chrome-extension', Parser::blocked( 'chrome-extension' ) );
		$this->assertSame( 'wasm-eval', Parser::blocked( 'WASM-EVAL' ) );
	}

	public function test_text_is_truncated_on_character_boundaries(): void {
		$text = Parser::text( str_repeat( 'é', 200 ), 255 );
		$this->assertSame( 1, preg_match( '//u', $text ) );
		$this->assertSame( 254, strlen( $text ) );
		$this->assertSame( 'a b', Parser::text( "a\x00\x07b", 10 ) );
	}

	public function test_rate_limiter_window(): void {
		$limiter = new RateLimiter( 3, 60 );
		$this->assertTrue( $limiter->hit( 'k', 1000 ) );
		$this->assertTrue( $limiter->hit( 'k', 1001 ) );
		$this->assertTrue( $limiter->hit( 'k', 1002 ) );
		$this->assertFalse( $limiter->hit( 'k', 1003 ) );
		$this->assertSame( 57, $limiter->retry_after( 'k', 1003 ) );
		$this->assertTrue( $limiter->hit( 'other', 1003 ) );
		$this->assertTrue( $limiter->hit( 'k', 1060 ) );
		$this->assertSame( 0, ( new RateLimiter( 1 ) )->retry_after( 'never', 5 ) );
	}

	public function test_store_install_creates_capped_table_schema(): void {
		$db = new FakeWpdb();
		( new Store( $db ) )->install();
		$sql = WpStubs::calls( 'dbDelta' )[0];
		$this->assertStringContainsString( 'CREATE TABLE wp_security_headers_reports (', $sql );
		$this->assertStringContainsString( 'UNIQUE KEY hash (hash)', $sql );
		$this->assertStringContainsString( 'KEY last_seen (last_seen)', $sql );
		$this->assertSame( Store::DB_VERSION, WpStubs::$options[ Store::DB_VERSION_OPTION ] );
	}

	public function test_maybe_install_runs_once(): void {
		$store = new Store( new FakeWpdb() );
		$store->maybe_install();
		$store->maybe_install();
		$this->assertCount( 1, WpStubs::calls( 'dbDelta' ) );
	}

	/**
	 * @return array<string,mixed>
	 */
	private static function violation(): array {
		return Parser::parse( self::legacy(), 'application/csp-report' )[0];
	}

	public function test_store_record_upserts_and_prunes_new_rows(): void {
		$db        = new FakeWpdb();
		$db->var   = 11;
		$store     = new Store( $db );
		$store->record( self::violation(), 1800000000, 10 );

		$this->assertCount( 3, $db->queries );
		$this->assertStringStartsWith( 'INSERT INTO `wp_security_headers_reports`', $db->queries[0] );
		$this->assertStringContainsString( 'ON DUPLICATE KEY UPDATE hits = hits + 1', $db->queries[0] );
		$this->assertStringContainsString( "'" . Store::hash( self::violation() ) . "'", $db->queries[0] );
		$this->assertStringContainsString( "'2027-01-15 08:00:00'", $db->queries[0] );
		$this->assertSame( 'SELECT COUNT(*) FROM `wp_security_headers_reports`', $db->queries[1] );
		$this->assertSame( 'DELETE FROM `wp_security_headers_reports` ORDER BY last_seen ASC, id ASC LIMIT 1', $db->queries[2] );
	}

	public function test_store_does_not_prune_on_duplicate_or_under_cap(): void {
		$db               = new FakeWpdb();
		$db->query_result = 2;
		( new Store( $db ) )->record( self::violation(), 1800000000, 10 );
		$this->assertCount( 1, $db->queries );

		$db        = new FakeWpdb();
		$db->var   = 10;
		( new Store( $db ) )->record( self::violation(), 1800000000, 10 );
		$this->assertCount( 2, $db->queries );
	}

	public function test_hash_ignores_the_document(): void {
		$a             = self::violation();
		$b             = $a;
		$b['document'] = 'https://example.org/other/';
		$c             = $a;
		$c['line']     = 99;
		$this->assertSame( Store::hash( $a ), Store::hash( $b ) );
		$this->assertNotSame( Store::hash( $a ), Store::hash( $c ) );
	}

	public function test_store_rows_count_clear_and_drop(): void {
		$db          = new FakeWpdb();
		$db->results = array( array( 'directive' => 'img-src' ) );
		$db->var     = '4';
		$store       = new Store( $db );
		$this->assertSame( array( array( 'directive' => 'img-src' ) ), $store->rows( 20, 40 ) );
		$this->assertStringEndsWith( 'ORDER BY hits DESC, last_seen DESC LIMIT 20 OFFSET 40', $db->queries[0] );
		$this->assertSame( 4, $store->count() );
		$store->clear();
		$this->assertSame( 'DELETE FROM `wp_security_headers_reports`', end( $db->queries ) );
		$store->drop();
		$this->assertSame( 'DROP TABLE IF EXISTS `wp_security_headers_reports`', end( $db->queries ) );
		$db->results = null;
		$this->assertSame( array(), $store->rows( 5 ) );
	}

	/**
	 * @return array<string,array{0:string,1:string,2:string}>
	 */
	public function suggestions(): array {
		return array(
			'third-party script'  => array( 'script-src-elem', 'https://cdn.example.com/lib.js', 'https://cdn.example.com, add it to script-src' ),
			'font with port'      => array( 'font-src', 'https://fonts.example:8443/a.woff2', 'https://fonts.example:8443, add it to font-src' ),
			'inline script'       => array( 'script-src-elem', 'inline', 'Turn on nonces' ),
			'inline handler'      => array( 'script-src-attr', 'inline', 'addEventListener' ),
			'inline style'        => array( 'style-src-elem', 'inline', "'unsafe-inline' to style-src" ),
			'eval'                => array( 'script-src', 'eval', "'unsafe-eval'" ),
			'wasm'                => array( 'script-src', 'wasm-eval', "'wasm-unsafe-eval'" ),
			'data image'          => array( 'img-src', 'data', 'Add data: to img-src' ),
			'data script'         => array( 'script-src-elem', 'data', 'risky' ),
			'blob worker'         => array( 'worker-src', 'blob', 'Add blob: to worker-src' ),
			'framing'             => array( 'frame-ancestors', 'https://evil.example', 'Allowed framing origins' ),
			'plain http'          => array( 'img-src', 'http://old.example/a.png', 'plain HTTP' ),
			'unknown'             => array( 'connect-src', '', 'connect-src' ),
		);
	}

	/**
	 * @dataProvider suggestions
	 */
	public function test_suggestions( string $directive, string $blocked, string $expected ): void {
		$this->assertStringContainsString(
			$expected,
			Suggest::for_violation(
				array(
					'directive'   => $directive,
					'blocked_uri' => $blocked,
				)
			)
		);
	}
}
