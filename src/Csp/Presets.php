<?php
/**
 * Ready-made Content-Security-Policy presets.
 *
 * @package Saizul\SecurityHeaders
 */

namespace Saizul\SecurityHeaders\Csp;

defined( 'ABSPATH' ) || exit;

/**
 * Starting points for the CSP builder. Every preset is meant to be tried in
 * Report-Only mode first and tightened with the violations screen.
 */
final class Presets {

	const STRICT      = 'strict';
	const WORDPRESS   = 'wordpress';
	const WOOCOMMERCE = 'woocommerce';

	/**
	 * Preset slugs.
	 *
	 * @return string[]
	 */
	public static function slugs(): array {
		return array( self::STRICT, self::WORDPRESS, self::WOOCOMMERCE );
	}

	/**
	 * Translated labels.
	 *
	 * @return array<string,string>
	 */
	public static function labels(): array {
		return array(
			self::STRICT      => __( 'Strict (nonce + strict-dynamic, for sites you control end to end)', 'wp-security-headers' ),
			self::WORDPRESS   => __( 'WordPress-compatible (works with most themes and plugins)', 'wp-security-headers' ),
			self::WOOCOMMERCE => __( 'WooCommerce-compatible (adds Stripe, PayPal and Google Pay)', 'wp-security-headers' ),
		);
	}

	/**
	 * Whether a preset relies on the per-request nonce.
	 *
	 * @param string $slug Preset.
	 */
	public static function needs_nonce( string $slug ): bool {
		return self::STRICT === $slug;
	}

	/**
	 * Directives of a preset (directive => sources). Unknown slugs fall back
	 * to the WordPress preset.
	 *
	 * @param string $slug Preset.
	 * @return array<string,string[]>
	 */
	public static function get( string $slug ): array {
		$wordpress = array(
			'default-src' => array( "'self'" ),
			'script-src'  => array( "'self'", "'unsafe-inline'" ),
			'style-src'   => array( "'self'", "'unsafe-inline'" ),
			'img-src'     => array( "'self'", 'data:', 'https:' ),
			'font-src'    => array( "'self'", 'data:' ),
			'connect-src' => array( "'self'" ),
			'media-src'   => array( "'self'", 'https:' ),
			'frame-src'   => array( "'self'", 'https://www.youtube.com', 'https://www.youtube-nocookie.com', 'https://player.vimeo.com' ),
			'worker-src'  => array( "'self'", 'blob:' ),
			'object-src'  => array( "'none'" ),
			'base-uri'    => array( "'self'" ),
			'form-action' => array( "'self'" ),
		);

		switch ( $slug ) {
			case self::STRICT:
				// Google's "strict CSP": modern browsers only honour the nonce and
				// 'strict-dynamic'; https: and 'unsafe-inline' are ignored by them
				// and only keep very old browsers working.
				return array(
					'default-src' => array( "'self'" ),
					'script-src'  => array( "'strict-dynamic'", 'https:', "'unsafe-inline'" ),
					'style-src'   => array( "'self'", "'unsafe-inline'" ),
					'img-src'     => array( "'self'", 'data:' ),
					'font-src'    => array( "'self'" ),
					'connect-src' => array( "'self'" ),
					'frame-src'   => array( "'self'" ),
					'object-src'  => array( "'none'" ),
					'base-uri'    => array( "'none'" ),
					'form-action' => array( "'self'" ),
				);

			case self::WOOCOMMERCE:
				$shop = array(
					'script-src'  => array( 'https://js.stripe.com', 'https://*.paypal.com', 'https://www.paypalobjects.com', 'https://pay.google.com' ),
					'frame-src'   => array( 'https://js.stripe.com', 'https://hooks.stripe.com', 'https://*.paypal.com', 'https://pay.google.com' ),
					'connect-src' => array( 'https://api.stripe.com', 'https://*.paypal.com', 'https://pay.google.com' ),
					'form-action' => array( 'https://*.paypal.com' ),
				);
				foreach ( $shop as $directive => $sources ) {
					$wordpress[ $directive ] = array_values( array_unique( array_merge( $wordpress[ $directive ], $sources ) ) );
				}
				return $wordpress;
		}

		return $wordpress;
	}
}
