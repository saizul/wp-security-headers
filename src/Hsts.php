<?php
/**
 * Strict-Transport-Security value and preload checklist.
 *
 * @package Saizul\SecurityHeaders
 */

namespace Saizul\SecurityHeaders;

defined( 'ABSPATH' ) || exit;

/**
 * HSTS helpers.
 */
final class Hsts {

	const ONE_YEAR   = 31536000;
	const SIX_MONTHS = 15552000;

	/**
	 * Header value, for example `max-age=31536000; includeSubDomains; preload`.
	 *
	 * @param array<string,mixed> $settings Settings.
	 */
	public static function value( array $settings ): string {
		$value = 'max-age=' . max( 0, (int) $settings['hsts_max_age'] );
		if ( ! empty( $settings['hsts_include_subdomains'] ) ) {
			$value .= '; includeSubDomains';
		}
		if ( ! empty( $settings['hsts_preload'] ) ) {
			$value .= '; preload';
		}

		return $value;
	}

	/**
	 * Max-age choices offered in the settings screen.
	 *
	 * @return array<int,string>
	 */
	public static function max_age_choices(): array {
		return array(
			300              => __( '5 minutes (testing)', 'wp-security-headers' ),
			86400            => __( '1 day', 'wp-security-headers' ),
			604800           => __( '1 week', 'wp-security-headers' ),
			2592000          => __( '30 days', 'wp-security-headers' ),
			self::SIX_MONTHS => __( '180 days', 'wp-security-headers' ),
			self::ONE_YEAR   => __( '1 year (needed for preload)', 'wp-security-headers' ),
			63072000         => __( '2 years (recommended once stable)', 'wp-security-headers' ),
		);
	}

	/**
	 * Checklist for the current HSTS settings and site address.
	 *
	 * @param array<string,mixed> $settings Settings.
	 * @param string              $home_url Home URL of the site.
	 * @return array<int,array{severity:string,message:string}>
	 */
	public static function warnings( array $settings, string $home_url ): array {
		$out    = array();
		$scheme = strtolower( (string) wp_parse_url( $home_url, PHP_URL_SCHEME ) );
		$host   = strtolower( (string) wp_parse_url( $home_url, PHP_URL_HOST ) );

		if ( empty( $settings['hsts_enabled'] ) ) {
			return $out;
		}

		if ( 'https' !== $scheme ) {
			$out[] = self::item( 'high', __( 'Your site address does not start with https://. Browsers ignore HSTS sent over plain HTTP, so the header is only sent on HTTPS requests. Move the site to HTTPS first.', 'wp-security-headers' ) );
		}

		$age = (int) $settings['hsts_max_age'];
		if ( $age < self::SIX_MONTHS ) {
			$out[] = self::item( 'info', __( 'A short max-age is a good way to start. Raise it to at least 1 year once every page works over HTTPS.', 'wp-security-headers' ) );
		}

		if ( ! empty( $settings['hsts_include_subdomains'] ) ) {
			$out[] = self::item( 'medium', __( 'includeSubDomains applies to every subdomain (www, shop, staging, mail web interfaces and so on). Each of them must serve a valid HTTPS certificate, or visitors cannot open it until max-age expires.', 'wp-security-headers' ) );
		}

		if ( empty( $settings['hsts_preload'] ) ) {
			return $out;
		}

		$out[] = self::item( 'high', __( 'Preload is hard to undo: browsers ship the list, and removal takes months. Only submit your domain at hstspreload.org when you are sure every subdomain will stay on HTTPS.', 'wp-security-headers' ) );
		if ( $age < self::ONE_YEAR ) {
			$out[] = self::item( 'high', __( 'The preload list requires max-age of at least 31536000 seconds (1 year).', 'wp-security-headers' ) );
		}
		if ( empty( $settings['hsts_include_subdomains'] ) ) {
			$out[] = self::item( 'high', __( 'The preload list requires includeSubDomains.', 'wp-security-headers' ) );
		}
		$out[] = self::item( 'medium', __( 'http:// must redirect to https:// on the same host before any other redirect (for example http://example.com to https://example.com, not straight to https://www.example.com).', 'wp-security-headers' ) );

		$labels = array_values( array_filter( explode( '.', $host ) ) );
		if ( count( $labels ) > 2 ) {
			$out[] = self::item(
				'medium',
				sprintf(
					/* translators: %s: host name of the site. */
					__( 'Preloading is done for the registrable domain, not for %s. The header must also be sent by the bare domain (for example by your host or CDN), with the same settings.', 'wp-security-headers' ),
					$host
				)
			);
		}

		return $out;
	}

	/**
	 * One checklist item.
	 *
	 * @param string $severity Severity.
	 * @param string $message  Message.
	 * @return array{severity:string,message:string}
	 */
	private static function item( string $severity, string $message ): array {
		return array(
			'severity' => $severity,
			'message'  => $message,
		);
	}
}
