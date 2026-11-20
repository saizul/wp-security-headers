<?php
declare(strict_types=1);

namespace Saizul\SecurityHeaders\Tests\Unit;

use Saizul\SecurityHeaders\Reports\Endpoint;
use Saizul\SecurityHeaders\Reports\Parser;
use Saizul\SecurityHeaders\Reports\ReportStore;
use Saizul\SecurityHeaders\Settings;
use Saizul\SecurityHeaders\Tests\WpTestCase;
use WP_Error;
use WP_REST_Request;
use WP_REST_Response;
use WpStubs;

/**
 * In-memory store for endpoint tests.
 */
final class MemoryStore implements ReportStore {
	/** @var array<int,array{0:array<string,mixed>,1:int,2:int}> */
	public $recorded = array();

	public function record( array $violation, int $now, int $cap ): void {
		$this->recorded[] = array( $violation, $now, $cap );
	}

	public function count(): int {
		return count( $this->recorded );
	}

	public function rows( int $limit, int $offset = 0 ): array {
		return array_slice( array_column( $this->recorded, 0 ), $offset, $limit );
	}

	public function clear(): void {
		$this->recorded = array();
	}
}

final class EndpointTest extends WpTestCase {

	/** @var MemoryStore */
	private $store;

	/** @var int */
	private $now = 1800000000;

	protected function setUp(): void {
		parent::setUp();
		$this->store = new MemoryStore();
	}

	/**
	 * @param array<string,mixed> $settings Overrides.
	 */
	private function endpoint( array $settings = array() ): Endpoint {
		$settings = self::settings(
			array_merge(
				array(
					'csp_mode'          => Settings::CSP_REPORT_ONLY,
					'csp_report'        => true,
					'report_rate_limit' => 3,
					'report_cap'        => 250,
				),
				$settings
			)
		);

		return new Endpoint(
			$this->store,
			static function () use ( $settings ) {
				return $settings;
			},
			function () {
				return $this->now;
			}
		);
	}

	private static function request( string $body, string $type = 'application/csp-report' ): WP_REST_Request {
		$request = new WP_REST_Request( 'POST', '/security-headers/v1/report' );
		$request->set_body( $body );
		$request->set_header( 'Content-Type', $type );
		return $request;
	}

	/**
	 * @param mixed $response Response.
	 */
	private static function status( $response ): int {
		if ( $response instanceof WP_Error ) {
			return (int) $response->get_error_data()['status'];
		}
		return $response->get_status();
	}

	public function test_route_is_registered_as_public_post(): void {
		$endpoint = $this->endpoint();
		$endpoint->register();
		do_action( 'rest_api_init' );
		$route = WpStubs::$registry['routes']['security-headers/v1/report'];
		$this->assertSame( 'POST', $route['methods'] );
		$this->assertSame( '__return_true', $route['permission_callback'] );
		$this->assertSame( array( $endpoint, 'handle' ), $route['callback'] );
		$this->assertSame( 'https://example.org/wp-json/security-headers/v1/report', Endpoint::url() );
	}

	public function test_valid_report_is_stored_and_answered_with_204(): void {
		$response = $this->endpoint()->handle( self::request( ReportsTest::legacy() ) );
		$this->assertInstanceOf( WP_REST_Response::class, $response );
		$this->assertSame( 204, $response->get_status() );
		$this->assertCount( 1, $this->store->recorded );
		list( $violation, $now, $cap ) = $this->store->recorded[0];
		$this->assertSame( 'https://example.org/shop/', $violation['document'] );
		$this->assertSame( $this->now, $now );
		$this->assertSame( 250, $cap );
	}

	public function test_reporting_off_is_refused(): void {
		$this->assertSame( 403, self::status( $this->endpoint( array( 'csp_mode' => Settings::CSP_OFF ) )->handle( self::request( ReportsTest::legacy() ) ) ) );
		$this->assertSame( 403, self::status( $this->endpoint( array( 'csp_report' => false ) )->handle( self::request( ReportsTest::legacy() ) ) ) );
		$this->assertSame( array(), $this->store->recorded );
	}

	public function test_oversized_body_is_refused_before_parsing(): void {
		$response = $this->endpoint()->handle( self::request( str_repeat( 'x', Parser::MAX_BYTES + 1 ) ) );
		$this->assertSame( 413, self::status( $response ) );
		$this->assertSame( array(), WpStubs::$transients, 'oversized bodies do not use rate-limit budget' );
	}

	public function test_wrong_content_type_and_invalid_json(): void {
		$this->assertSame( 415, self::status( $this->endpoint()->handle( self::request( ReportsTest::legacy(), 'text/plain' ) ) ) );
		$this->assertSame( 400, self::status( $this->endpoint()->handle( self::request( '{oops', 'application/json' ) ) ) );
	}

	public function test_reports_about_other_sites_are_dropped(): void {
		$body     = ReportsTest::legacy( array( 'document-uri' => 'https://attacker.example/' ) );
		$response = $this->endpoint()->handle( self::request( $body ) );
		$this->assertSame( 400, self::status( $response ) );
		$this->assertSame( array(), $this->store->recorded );
	}

	public function test_allowed_hosts_filter(): void {
		add_filter(
			'security_headers_report_hosts',
			static function ( $hosts ) {
				$hosts[] = 'SHOP.EXAMPLE.ORG';
				return $hosts;
			}
		);
		$body = ReportsTest::legacy( array( 'document-uri' => 'https://shop.example.org/cart/' ) );
		$this->assertSame( 204, self::status( $this->endpoint()->handle( self::request( $body ) ) ) );
	}

	public function test_rate_limit_per_client(): void {
		$endpoint = $this->endpoint();
		for ( $i = 0; $i < 3; $i++ ) {
			$this->assertSame( 204, self::status( $endpoint->handle( self::request( ReportsTest::legacy() ) ) ) );
		}
		$limited = $endpoint->handle( self::request( ReportsTest::legacy() ) );
		$this->assertSame( 429, self::status( $limited ) );
		$this->assertSame( '60', $limited->headers['Retry-After'] );
		$this->assertCount( 3, $this->store->recorded );

		// Another client still gets through.
		$_SERVER['REMOTE_ADDR'] = '203.0.113.9';
		$this->assertSame( 204, self::status( $endpoint->handle( self::request( ReportsTest::legacy() ) ) ) );

		// The window resets.
		$_SERVER['REMOTE_ADDR'] = '198.51.100.10';
		$this->now += 61;
		$this->assertSame( 204, self::status( $endpoint->handle( self::request( ReportsTest::legacy() ) ) ) );
	}

	public function test_global_rate_limit(): void {
		$endpoint = $this->endpoint( array( 'report_rate_limit' => 600 ) );
		for ( $i = 0; $i < Endpoint::GLOBAL_LIMIT; $i++ ) {
			$_SERVER['REMOTE_ADDR'] = '192.0.2.' . ( $i % 250 );
			$endpoint->handle( self::request( ReportsTest::legacy() ) );
		}
		$_SERVER['REMOTE_ADDR'] = '203.0.113.200';
		$this->assertSame( 429, self::status( $endpoint->handle( self::request( ReportsTest::legacy() ) ) ) );
	}

	public function test_client_key_hides_the_ip_and_honours_the_filter(): void {
		$key = Endpoint::client_key();
		$this->assertSame( 32, strlen( $key ) );
		$this->assertStringNotContainsString( '198.51.100.10', $key );
		add_filter(
			'security_headers_client_ip',
			static function () {
				return '203.0.113.1';
			}
		);
		$this->assertNotSame( $key, Endpoint::client_key() );
	}
}
