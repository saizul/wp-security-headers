<?php
/**
 * Suggestions for violations.
 *
 * @package Saizul\SecurityHeaders
 */

namespace Saizul\SecurityHeaders\Reports;

defined( 'ABSPATH' ) || exit;

/**
 * Turns a stored violation into a concrete next step for the policy.
 */
final class Suggest {

	/**
	 * The directive to edit for a reported (effective) directive.
	 *
	 * @param string $directive Directive from the report, e.g. script-src-elem.
	 */
	public static function base_directive( string $directive ): string {
		return (string) preg_replace( '/-(elem|attr)$/', '', strtolower( $directive ) );
	}

	/**
	 * Origin of a URL (scheme://host[:port]), or ''.
	 *
	 * @param string $url URL.
	 */
	public static function origin( string $url ): string {
		$parts = wp_parse_url( $url );
		if ( ! is_array( $parts ) || ! isset( $parts['scheme'], $parts['host'] ) ) {
			return '';
		}

		return strtolower( $parts['scheme'] ) . '://' . strtolower( $parts['host'] ) . ( isset( $parts['port'] ) ? ':' . (int) $parts['port'] : '' );
	}

	/**
	 * A suggestion for one violation.
	 *
	 * @param array<string,mixed> $row Violation (directive, blocked_uri).
	 */
	public static function for_violation( array $row ): string {
		$directive = strtolower( (string) ( $row['directive'] ?? '' ) );
		$blocked   = (string) ( $row['blocked_uri'] ?? '' );
		$base      = self::base_directive( $directive );
		$is_script = 0 === strpos( $directive, 'script-src' );

		if ( 'inline' === $blocked ) {
			if ( 'script-src-attr' === $directive || 'style-src-attr' === $directive ) {
				return __( "An inline event handler or style attribute was blocked (for example onclick=\"...\"). Rewrite it with addEventListener() or a stylesheet; 'unsafe-hashes' with a hash is the narrow alternative.", 'wp-security-headers' );
			}
			if ( $is_script ) {
				return __( "An inline <script> was blocked. Turn on nonces (scripts printed with wp_add_inline_script() and wp_print_inline_script_tag() get one automatically), or move the code into a file. Adding 'unsafe-inline' to script-src works but weakens the policy.", 'wp-security-headers' );
			}

			return sprintf(
				/* translators: %s: directive name. */
				__( "An inline <style> was blocked. Add 'unsafe-inline' to %s (inline styles are a much smaller risk than inline scripts).", 'wp-security-headers' ),
				$base
			);
		}
		if ( 'eval' === $blocked ) {
			return __( "A script used eval() or new Function(). Find the script in \"Source\" and add 'unsafe-eval' to script-src only if you trust it and cannot replace it.", 'wp-security-headers' );
		}
		if ( 'wasm-eval' === $blocked ) {
			return __( "WebAssembly was blocked. Add 'wasm-unsafe-eval' to script-src if the site needs it.", 'wp-security-headers' );
		}
		if ( in_array( $blocked, array( 'data', 'blob' ), true ) ) {
			if ( $is_script ) {
				return sprintf(
					/* translators: %s: data: or blob:. */
					__( 'A script was loaded from %s. Allowing it in script-src is risky; find the plugin that does this first.', 'wp-security-headers' ),
					$blocked . ':'
				);
			}

			return sprintf(
				/* translators: 1: data: or blob:, 2: directive name. */
				__( 'Add %1$s to %2$s.', 'wp-security-headers' ),
				$blocked . ':',
				$base
			);
		}
		if ( 'frame-ancestors' === $directive ) {
			return __( 'Another site tried to embed this page. If you trust it, add its origin to "Allowed framing origins".', 'wp-security-headers' );
		}

		$origin = self::origin( $blocked );
		if ( '' !== $origin ) {
			if ( 0 === strpos( $origin, 'http://' ) ) {
				return sprintf(
					/* translators: %s: origin. */
					__( '%s is plain HTTP. Load it over HTTPS (upgrade-insecure-requests does this automatically when it is on and the host supports HTTPS).', 'wp-security-headers' ),
					$origin
				);
			}

			return sprintf(
				/* translators: 1: origin such as https://cdn.example.com, 2: directive name. */
				__( 'If you trust %1$s, add it to %2$s.', 'wp-security-headers' ),
				$origin,
				$base
			);
		}

		return sprintf(
			/* translators: %s: directive name. */
			__( 'Check the source file and decide whether %s should allow it.', 'wp-security-headers' ),
			'' !== $base ? $base : __( 'the policy', 'wp-security-headers' )
		);
	}
}
