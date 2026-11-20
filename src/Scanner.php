<?php
/**
 * Fetches a page server-side and grades its headers.
 *
 * @package Saizul\SecurityHeaders
 */

namespace Saizul\SecurityHeaders;

defined( 'ABSPATH' ) || exit;

/**
 * "Scan my site": a GET request to the home page from the server itself,
 * the same way a visitor would load it.
 */
final class Scanner {

	const LAST_SCAN_OPTION = 'wp_security_headers_last_scan';
	const MAX_REDIRECTS    = 3;

	/**
	 * Scan a URL (the home page by default).
	 *
	 * @param string $url URL to scan, '' for the home page.
	 * @return array<string,mixed>|\WP_Error
	 */
	public function scan( string $url = '' ) {
		$url = '' === $url ? home_url( '/' ) : $url;
		if ( ! preg_match( '#^https?://#i', $url ) ) {
			return new \WP_Error( 'security_headers_bad_url', __( 'Only http:// and https:// URLs can be scanned.', 'wp-security-headers' ) );
		}

		$visited = array();
		for ( $i = 0; $i <= self::MAX_REDIRECTS; $i++ ) {
			$visited[] = $url;
			$response  = wp_remote_get(
				$url,
				array(
					'timeout'     => 15,
					'redirection' => 0,
					// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Core filter for loopback requests.
					'sslverify'   => (bool) apply_filters( 'https_local_ssl_verify', false ),
					'user-agent'  => 'wp-security-headers-scanner/' . Plugin::VERSION,
					'headers'     => array( 'Accept' => 'text/html' ),
				)
			);
			if ( is_wp_error( $response ) ) {
				return new \WP_Error(
					'security_headers_scan_failed',
					sprintf(
						/* translators: 1: URL, 2: error message. */
						__( 'Could not load %1$s: %2$s. Loopback requests may be blocked by your host or firewall; try "wp security-headers scan" or an online scanner.', 'wp-security-headers' ),
						$url,
						$response->get_error_message()
					)
				);
			}

			$status   = (int) wp_remote_retrieve_response_code( $response );
			$location = (string) wp_remote_retrieve_header( $response, 'location' );
			if ( $status >= 300 && $status < 400 && '' !== $location ) {
				$url = self::resolve( $url, $location );
				continue;
			}

			$headers = self::headers( $response );
			$https   = 0 === stripos( $url, 'https://' );

			return array(
				'url'       => $url,
				'redirects' => array_slice( $visited, 0, -1 ),
				'status'    => $status,
				'https'     => $https,
				'headers'   => $headers,
				'result'    => Grader::grade( $headers, $https ),
				'time'      => time(),
			);
		}

		return new \WP_Error( 'security_headers_too_many_redirects', __( 'Too many redirects.', 'wp-security-headers' ) );
	}

	/**
	 * Scan and remember the result for the settings screen.
	 *
	 * @param string $url URL, '' for the home page.
	 * @return array<string,mixed>|\WP_Error
	 */
	public function scan_and_store( string $url = '' ) {
		$result = $this->scan( $url );
		if ( ! is_wp_error( $result ) ) {
			update_option( self::LAST_SCAN_OPTION, $result, false );
		}

		return $result;
	}

	/**
	 * Last stored scan, or null.
	 *
	 * @return array<string,mixed>|null
	 */
	public static function last(): ?array {
		$last = get_option( self::LAST_SCAN_OPTION, null );

		return is_array( $last ) && isset( $last['result'] ) ? $last : null;
	}

	/**
	 * Response headers as lower-case name => list of values.
	 *
	 * @param array<string,mixed> $response HTTP API response.
	 * @return array<string,string[]>
	 */
	public static function headers( $response ): array {
		$raw = wp_remote_retrieve_headers( $response );
		$out = array();
		if ( is_object( $raw ) && method_exists( $raw, 'getAll' ) ) {
			$raw = $raw->getAll();
		}
		if ( ! is_array( $raw ) ) {
			return $out;
		}
		foreach ( $raw as $name => $value ) {
			foreach ( (array) $value as $item ) {
				if ( is_scalar( $item ) ) {
					$out[ strtolower( (string) $name ) ][] = (string) $item;
				}
			}
		}

		return $out;
	}

	/**
	 * Resolve a Location header against the current URL.
	 *
	 * @param string $base     Current URL.
	 * @param string $location Location header.
	 */
	public static function resolve( string $base, string $location ): string {
		if ( preg_match( '#^https?://#i', $location ) ) {
			return $location;
		}
		$parts  = wp_parse_url( $base );
		$origin = ( $parts['scheme'] ?? 'https' ) . '://' . ( $parts['host'] ?? '' ) . ( isset( $parts['port'] ) ? ':' . $parts['port'] : '' );
		if ( 0 === strpos( $location, '//' ) ) {
			return ( $parts['scheme'] ?? 'https' ) . ':' . $location;
		}
		if ( 0 === strpos( $location, '/' ) ) {
			return $origin . $location;
		}
		$path = isset( $parts['path'] ) ? preg_replace( '#/[^/]*$#', '/', $parts['path'] ) : '/';

		return $origin . $path . $location;
	}
}
