<?php
/**
 * Per-request CSP nonce.
 *
 * @package Saizul\SecurityHeaders
 */

namespace Saizul\SecurityHeaders;

defined( 'ABSPATH' ) || exit;

/**
 * One random nonce per request, shared by the CSP header and the script tags
 * WordPress prints through wp_get_script_tag() and wp_get_inline_script_tag().
 */
final class Nonce {

	/**
	 * Nonce of this request.
	 *
	 * @var string|null
	 */
	private static $value;

	/**
	 * The nonce (base64, 128 bits of randomness).
	 */
	public static function value(): string {
		if ( null === self::$value ) {
			// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- CSP nonces are base64 by specification.
			self::$value = base64_encode( random_bytes( 16 ) );
		}

		return self::$value;
	}

	/**
	 * Forget the nonce (tests, long-running processes).
	 */
	public static function reset(): void {
		self::$value = null;
	}

	/**
	 * Add the nonce to script tag attributes. Hooked to `wp_script_attributes`
	 * and `wp_inline_script_attributes`.
	 *
	 * @param mixed $attributes Attributes.
	 * @return mixed
	 */
	public static function add_attribute( $attributes ) {
		if ( ! is_array( $attributes ) ) {
			return $attributes;
		}
		$attributes['nonce'] = self::value();

		return $attributes;
	}
}
