<?php
/**
 * Plugin Name: Security Headers tweaks (example)
 * Description: Example must-use plugin showing the Security Headers filters. Copy to wp-content/mu-plugins/ and edit.
 *
 * @package Saizul\SecurityHeaders
 */

defined( 'ABSPATH' ) || exit;

/*
 * Add a source to the CSP for one page only, for example a booking widget
 * on /book/. Headers are name/value pairs; edit the policy with the
 * Policy class so the result stays valid.
 */
add_filter(
	'security_headers_headers',
	static function ( array $headers, string $area ): array {
		if ( 'front' !== $area || ! isset( $_SERVER['REQUEST_URI'] ) || 0 !== strpos( (string) $_SERVER['REQUEST_URI'], '/book/' ) ) {
			return $headers;
		}
		foreach ( $headers as $i => $header ) {
			if ( in_array( $header[0], array( 'Content-Security-Policy', 'Content-Security-Policy-Report-Only' ), true ) && false !== strpos( $header[1], 'default-src' ) ) {
				$policy          = \Saizul\SecurityHeaders\Csp\Policy::parse( $header[1] )
					->add( 'script-src', array( 'https://widgets.booking.example' ) )
					->add( 'frame-src', array( 'https://widgets.booking.example' ) );
				$headers[ $i ][1] = $policy->serialize();
			}
		}
		return $headers;
	},
	10,
	2
);

/*
 * The site answers on a second domain: accept violation reports for both.
 */
add_filter(
	'security_headers_report_hosts',
	static function ( array $hosts ): array {
		$hosts[] = 'shop.example.com';
		return $hosts;
	}
);

/*
 * Behind a trusted reverse proxy (Cloudflare, a load balancer), rate-limit
 * reports by the real client address. Only do this if the proxy always sets
 * the header, or clients can spoof it.
 */
add_filter(
	'security_headers_client_ip',
	static function ( string $ip ): string {
		if ( isset( $_SERVER['HTTP_CF_CONNECTING_IP'] ) ) {
			return sanitize_text_field( wp_unslash( $_SERVER['HTTP_CF_CONNECTING_IP'] ) );
		}
		return $ip;
	}
);

/*
 * Only let users who can install plugins change the headers, scan and see
 * the violations (the default is manage_options).
 */
add_filter(
	'security_headers_capability',
	static function (): string {
		return 'install_plugins';
	}
);
