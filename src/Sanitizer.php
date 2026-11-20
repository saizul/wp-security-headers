<?php
/**
 * Settings sanitiser.
 *
 * @package Saizul\SecurityHeaders
 */

namespace Saizul\SecurityHeaders;

use Saizul\SecurityHeaders\Csp\Policy;
use Saizul\SecurityHeaders\Csp\Presets;

defined( 'ABSPATH' ) || exit;

/**
 * Turns raw form (or stored) input into valid settings. Pure: no WordPress
 * state is read, so it is easy to test. Accepts both the shape the settings
 * form posts and the shape that is stored, because update_option() runs the
 * sanitiser again on save.
 */
final class Sanitizer {

	const REFERRER_POLICIES = array(
		'no-referrer',
		'no-referrer-when-downgrade',
		'origin',
		'origin-when-cross-origin',
		'same-origin',
		'strict-origin',
		'strict-origin-when-cross-origin',
		'unsafe-url',
	);

	const FRAMING = array( 'deny', 'sameorigin', 'off' );
	const COOP    = array( 'same-origin', 'same-origin-allow-popups', 'unsafe-none' );
	const CORP    = array( 'same-origin', 'same-site', 'cross-origin' );

	/**
	 * Directives offered in the CSP builder.
	 */
	const EDITABLE_DIRECTIVES = array(
		'default-src',
		'script-src',
		'style-src',
		'img-src',
		'font-src',
		'connect-src',
		'media-src',
		'frame-src',
		'worker-src',
		'manifest-src',
		'object-src',
		'base-uri',
		'form-action',
	);

	const MAX_HSTS_AGE = 63072000;

	/**
	 * Sanitise settings.
	 *
	 * @param mixed               $input   Raw input.
	 * @param array<string,mixed> $current Current settings (used when input is not an array).
	 * @return array<string,mixed>
	 */
	public static function sanitize( $input, array $current ): array {
		$defaults = Settings::defaults();
		$current  = array_merge( $defaults, array_intersect_key( $current, $defaults ) );
		if ( ! is_array( $input ) ) {
			return $current;
		}

		$out = array();
		foreach ( array( 'hsts_enabled', 'hsts_include_subdomains', 'hsts_preload', 'nosniff', 'csp_nonce', 'csp_upgrade_insecure', 'csp_report', 'apply_admin', 'apply_login', 'remove_powered_by' ) as $key ) {
			$out[ $key ] = self::bool( $input[ $key ] ?? false );
		}

		$out['hsts_max_age'] = self::int( $input['hsts_max_age'] ?? $defaults['hsts_max_age'], 0, self::MAX_HSTS_AGE );
		if ( $out['hsts_preload'] ) {
			// The preload list rejects anything weaker, so do not send a header that cannot be accepted.
			$out['hsts_include_subdomains'] = true;
			$out['hsts_max_age']            = max( $out['hsts_max_age'], 31536000 );
		}

		$out['referrer_policy'] = self::choice( $input['referrer_policy'] ?? '', self::REFERRER_POLICIES, '' );
		$out['framing']         = self::choice( $input['framing'] ?? '', self::FRAMING, 'off' );
		$out['frame_ancestors'] = self::origins( $input['frame_ancestors'] ?? array() );
		$out['coop']            = self::choice( $input['coop'] ?? '', self::COOP, '' );
		$out['corp']            = self::choice( $input['corp'] ?? '', self::CORP, '' );
		$out['permissions']     = self::permissions( $input['permissions'] ?? array() );

		$out['csp_mode']   = self::choice( $input['csp_mode'] ?? '', array( Settings::CSP_OFF, Settings::CSP_REPORT_ONLY, Settings::CSP_ENFORCE ), Settings::CSP_OFF );
		$out['csp_preset'] = self::choice( $input['csp_preset'] ?? '', Presets::slugs(), Presets::WORDPRESS );

		if ( ! empty( $input['apply_preset'] ) ) {
			$out['csp_directives'] = Presets::get( $out['csp_preset'] );
			if ( Presets::needs_nonce( $out['csp_preset'] ) ) {
				$out['csp_nonce'] = true;
			}
		} else {
			$out['csp_directives'] = self::directives( $input['csp_directives'] ?? array() );
		}

		$out['report_cap']        = self::int( $input['report_cap'] ?? $defaults['report_cap'], 50, 20000 );
		$out['report_rate_limit'] = self::int( $input['report_rate_limit'] ?? $defaults['report_rate_limit'], 1, 600 );

		return $out;
	}

	/**
	 * CSP directives from the builder (directive => space separated sources).
	 *
	 * @param mixed $input Raw input.
	 * @return array<string,string[]>
	 */
	public static function directives( $input ): array {
		if ( ! is_array( $input ) ) {
			return array();
		}
		$out = array();
		foreach ( self::EDITABLE_DIRECTIVES as $directive ) {
			if ( ! isset( $input[ $directive ] ) ) {
				continue;
			}
			$raw = $input[ $directive ];
			if ( is_string( $raw ) ) {
				$raw = wp_unslash( $raw );
			}
			$sources = Policy::sanitize_sources( $directive, $raw );
			if ( array() !== $sources ) {
				$out[ $directive ] = $sources;
			}
		}

		return $out;
	}

	/**
	 * Origins allowed to frame the site (frame-ancestors), one per line.
	 *
	 * @param mixed $input String or list.
	 * @return string[]
	 */
	public static function origins( $input ): array {
		if ( is_string( $input ) ) {
			$input = preg_split( '/[\s,]+/', wp_unslash( $input ), -1, PREG_SPLIT_NO_EMPTY );
		}
		if ( ! is_array( $input ) ) {
			return array();
		}
		$out = array();
		foreach ( $input as $origin ) {
			if ( ! is_string( $origin ) ) {
				continue;
			}
			$clean = Policy::sanitize_source( $origin );
			// Hosts and schemes only: keywords are set by the framing choice.
			if ( null === $clean || "'" === substr( $clean, 0, 1 ) || '*' === $clean || in_array( $clean, array( 'http:', 'https:', 'data:', 'blob:' ), true ) ) {
				continue;
			}
			if ( ! in_array( $clean, $out, true ) ) {
				$out[] = $clean;
			}
			if ( count( $out ) >= 20 ) {
				break;
			}
		}

		return $out;
	}

	/**
	 * Permissions-Policy choices. The form posts
	 * `feature => array( 'on' => '1', 'allow' => 'none|self' )`; the stored
	 * shape is `feature => 'none'|'self'`.
	 *
	 * @param mixed $input Raw input.
	 * @return array<string,string>
	 */
	public static function permissions( $input ): array {
		if ( ! is_array( $input ) ) {
			return array();
		}
		$flat = array();
		foreach ( $input as $feature => $value ) {
			if ( is_array( $value ) ) {
				if ( empty( $value['on'] ) ) {
					continue;
				}
				$value = isset( $value['allow'] ) && PermissionsPolicy::SELF === $value['allow'] ? PermissionsPolicy::SELF : PermissionsPolicy::NONE;
			}
			$flat[ (string) $feature ] = $value;
		}

		return PermissionsPolicy::sanitize( $flat );
	}

	/**
	 * Boolean from a checkbox or a stored value.
	 *
	 * @param mixed $value Raw value.
	 */
	public static function bool( $value ): bool {
		if ( is_string( $value ) ) {
			return in_array( strtolower( trim( $value ) ), array( '1', 'true', 'yes', 'on' ), true );
		}

		return (bool) $value;
	}

	/**
	 * Integer clamped to a range.
	 *
	 * @param mixed $value Raw value.
	 * @param int   $min   Minimum.
	 * @param int   $max   Maximum.
	 */
	public static function int( $value, int $min, int $max ): int {
		$value = is_numeric( $value ) ? (int) $value : $min;

		return max( $min, min( $max, $value ) );
	}

	/**
	 * One of a list of strings, or a fallback.
	 *
	 * @param mixed    $value    Raw value.
	 * @param string[] $allowed  Allowed values.
	 * @param string   $fallback Fallback.
	 */
	public static function choice( $value, array $allowed, string $fallback ): string {
		$value = is_string( $value ) ? strtolower( trim( $value ) ) : '';

		return in_array( $value, $allowed, true ) ? $value : $fallback;
	}
}
