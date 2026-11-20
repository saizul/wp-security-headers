<?php
/**
 * REST endpoint that receives CSP violation reports.
 *
 * @package Saizul\SecurityHeaders
 */

namespace Saizul\SecurityHeaders\Reports;

use Saizul\SecurityHeaders\Settings;

defined( 'ABSPATH' ) || exit;

/**
 * POST /wp-json/security-headers/v1/report
 *
 * Public on purpose: browsers send reports without cookies or nonces. To
 * keep it cheap and safe the endpoint only accepts reports while CSP
 * reporting is on, limits the body size, rate-limits per client and
 * globally, ignores reports about pages of other sites and stores at most
 * `report_cap` distinct violations.
 */
final class Endpoint {

	const NAMESPACE_V1 = 'security-headers/v1';
	const ROUTE        = '/report';

	/**
	 * Reports per minute accepted from all clients together.
	 */
	const GLOBAL_LIMIT = 600;

	/**
	 * Store.
	 *
	 * @var ReportStore
	 */
	private $store;

	/**
	 * Returns the current settings.
	 *
	 * @var callable
	 */
	private $settings;

	/**
	 * Returns the current time.
	 *
	 * @var callable
	 */
	private $clock;

	/**
	 * Constructor.
	 *
	 * @param ReportStore   $store    Store.
	 * @param callable|null $settings Returns settings; Settings::get() by default.
	 * @param callable|null $clock    Returns a timestamp; time() by default.
	 */
	public function __construct( ReportStore $store, ?callable $settings = null, ?callable $clock = null ) {
		$this->store    = $store;
		$this->settings = $settings ?? array( Settings::class, 'get' );
		$this->clock    = $clock ?? 'time';
	}

	/**
	 * Hook the route.
	 */
	public function register(): void {
		add_action( 'rest_api_init', array( $this, 'register_route' ) );
	}

	/**
	 * Absolute URL of the endpoint.
	 */
	public static function url(): string {
		return rest_url( self::NAMESPACE_V1 . self::ROUTE );
	}

	/**
	 * Register the REST route.
	 */
	public function register_route(): void {
		register_rest_route(
			self::NAMESPACE_V1,
			self::ROUTE,
			array(
				'methods'             => 'POST',
				'callback'            => array( $this, 'handle' ),
				// Browsers send reports anonymously; validation happens in handle().
				'permission_callback' => '__return_true',
			)
		);
	}

	/**
	 * Handle a report.
	 *
	 * @param \WP_REST_Request $request Request.
	 * @return \WP_REST_Response|\WP_Error
	 */
	public function handle( $request ) {
		$settings = (array) call_user_func( $this->settings );
		$now      = (int) call_user_func( $this->clock );

		if ( empty( $settings['csp_report'] ) || Settings::CSP_OFF === ( $settings['csp_mode'] ?? Settings::CSP_OFF ) ) {
			return new \WP_Error( 'security_headers_reporting_off', 'CSP reporting is switched off.', array( 'status' => 403 ) );
		}

		$body = (string) $request->get_body();
		if ( strlen( $body ) > Parser::MAX_BYTES ) {
			return new \WP_Error( 'security_headers_too_large', 'Report too large.', array( 'status' => 413 ) );
		}

		$limit  = max( 1, (int) ( $settings['report_rate_limit'] ?? 30 ) );
		$client = new RateLimiter( $limit, 60 );
		$global = new RateLimiter( self::GLOBAL_LIMIT, 60 );
		$key    = 'client:' . self::client_key();
		if ( ! $global->hit( 'global', $now ) || ! $client->hit( $key, $now ) ) {
			$response = new \WP_REST_Response(
				array(
					'code'    => 'security_headers_rate_limited',
					'message' => 'Too many reports.',
				),
				429
			);
			$response->header( 'Retry-After', (string) max( 1, $client->retry_after( $key, $now ) ) );

			return $response;
		}

		$violations = Parser::parse( $body, (string) $request->get_header( 'content_type' ) );
		if ( is_wp_error( $violations ) ) {
			return $violations;
		}

		$hosts    = self::allowed_hosts();
		$accepted = 0;
		$cap      = max( 1, (int) ( $settings['report_cap'] ?? 1000 ) );
		foreach ( $violations as $violation ) {
			$host = strtolower( (string) wp_parse_url( $violation['document'], PHP_URL_HOST ) );
			if ( ! in_array( $host, $hosts, true ) ) {
				continue;
			}
			$this->store->record( $violation, $now, $cap );
			++$accepted;
		}

		if ( 0 === $accepted ) {
			return new \WP_Error( 'security_headers_foreign_document', 'Reports must be about pages of this site.', array( 'status' => 400 ) );
		}

		return new \WP_REST_Response( null, 204 );
	}

	/**
	 * Hosts whose pages may be reported on.
	 *
	 * @return string[]
	 */
	public static function allowed_hosts(): array {
		$hosts = array_filter(
			array(
				strtolower( (string) wp_parse_url( home_url( '/' ), PHP_URL_HOST ) ),
				strtolower( (string) wp_parse_url( site_url( '/' ), PHP_URL_HOST ) ),
			)
		);

		/**
		 * Filters the hosts whose pages may send violation reports, for
		 * example when the same site answers on several domains.
		 *
		 * @param string[] $hosts Lower-case host names.
		 */
		$hosts = apply_filters( 'security_headers_report_hosts', array_values( array_unique( $hosts ) ) );

		return is_array( $hosts ) ? array_map( 'strtolower', array_map( 'strval', $hosts ) ) : array();
	}

	/**
	 * Anonymous key for the client: an HMAC of the IP address, so the address
	 * itself is never stored.
	 */
	public static function client_key(): string {
		$ip = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';

		/**
		 * Filters the client IP used for rate limiting. Only REMOTE_ADDR is
		 * trusted by default; behind a reverse proxy return the real address.
		 *
		 * @param string $ip IP address.
		 */
		$ip = (string) apply_filters( 'security_headers_client_ip', $ip );

		return substr( hash_hmac( 'sha256', $ip, wp_salt( 'nonce' ) ), 0, 32 );
	}
}
