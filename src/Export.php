<?php
/**
 * Server snippets (nginx and Apache) for people who prefer server configuration.
 *
 * @package Saizul\SecurityHeaders
 */

namespace Saizul\SecurityHeaders;

defined( 'ABSPATH' ) || exit;

/**
 * Turns the header list into server configuration.
 */
final class Export {

	const NGINX  = 'nginx';
	const APACHE = 'apache';

	/**
	 * Headers to export: the front-end headers for an HTTPS request, without
	 * a nonce (a static file cannot generate one per request).
	 *
	 * @param array<string,mixed> $settings   Settings.
	 * @param string              $report_url Report endpoint URL.
	 * @return array<int,array{0:string,1:string}>
	 */
	public static function headers( array $settings, string $report_url ): array {
		$settings['csp_nonce'] = false;

		return HeaderBuilder::build(
			$settings,
			array(
				'area'       => HeaderBuilder::AREA_FRONT,
				'https'      => true,
				'nonce'      => null,
				'report_url' => $report_url,
			)
		);
	}

	/**
	 * Notes printed above the snippet.
	 *
	 * @param array<string,mixed> $settings Settings.
	 * @return string[]
	 */
	public static function notes( array $settings ): array {
		$notes = array(
			__( 'Remove or switch off the plugin headers you move to the server, so they are not sent twice.', 'wp-security-headers' ),
		);
		if ( ! empty( $settings['csp_nonce'] ) && Settings::CSP_OFF !== $settings['csp_mode'] ) {
			$notes[] = __( 'Nonces are left out: the server cannot add a fresh nonce to each page. Keep the CSP in the plugin if you rely on nonces.', 'wp-security-headers' );
		}
		if ( ! empty( $settings['csp_report'] ) && Settings::CSP_OFF !== $settings['csp_mode'] ) {
			$notes[] = __( 'The report endpoint only accepts reports while the plugin CSP mode is Report-Only or Enforce. If you switch the plugin CSP off, remove report-uri, report-to and Reporting-Endpoints too.', 'wp-security-headers' );
		}
		if ( ! empty( $settings['hsts_enabled'] ) ) {
			$notes[] = __( 'Send Strict-Transport-Security from the HTTPS server block / virtual host only.', 'wp-security-headers' );
		}

		return $notes;
	}

	/**
	 * Snippet for a server.
	 *
	 * @param string                              $server  nginx or apache.
	 * @param array<int,array{0:string,1:string}> $headers Headers.
	 * @param string[]                            $notes   Notes, printed as comments.
	 */
	public static function render( string $server, array $headers, array $notes = array() ): string {
		return self::APACHE === $server ? self::apache( $headers, $notes ) : self::nginx( $headers, $notes );
	}

	/**
	 * Snippet for nginx: `add_header` lines for a server or location block.
	 *
	 * @param array<int,array{0:string,1:string}> $headers Headers.
	 * @param string[]                            $notes   Notes.
	 */
	public static function nginx( array $headers, array $notes = array() ): string {
		$lines = self::comments(
			array_merge(
				array(
					'Security headers exported from the Security Headers WordPress plugin.',
					'Put these lines in the server { } block. nginx drops inherited add_header',
					'lines in any location { } block that has its own add_header, so repeat them there.',
				),
				$notes
			)
		);
		foreach ( $headers as $header ) {
			$lines[] = 'add_header ' . $header[0] . ' "' . self::quote( $header[1] ) . '" always;';
		}
		if ( array() === $headers ) {
			$lines[] = '# No headers are switched on.';
		}

		return implode( "\n", $lines ) . "\n";
	}

	/**
	 * Apache: mod_headers block for the virtual host or .htaccess.
	 *
	 * @param array<int,array{0:string,1:string}> $headers Headers.
	 * @param string[]                            $notes   Notes.
	 */
	public static function apache( array $headers, array $notes = array() ): string {
		$lines   = self::comments(
			array_merge(
				array(
					'Security headers exported from the Security Headers WordPress plugin.',
					'Put this block in the <VirtualHost> or in .htaccess (needs mod_headers).',
				),
				$notes
			)
		);
		$lines[] = '<IfModule mod_headers.c>';
		foreach ( $headers as $header ) {
			$lines[] = '    Header always set ' . $header[0] . ' "' . self::quote( $header[1] ) . '"';
		}
		$lines[] = '</IfModule>';

		return implode( "\n", $lines ) . "\n";
	}

	/**
	 * Comment lines.
	 *
	 * @param string[] $notes Notes.
	 * @return string[]
	 */
	private static function comments( array $notes ): array {
		return array_map(
			static function ( $note ) {
				return '# ' . str_replace( array( "\r", "\n" ), ' ', $note );
			},
			$notes
		);
	}

	/**
	 * Escape a value for a double-quoted config string.
	 *
	 * @param string $value Value.
	 */
	public static function quote( string $value ): string {
		$value = str_replace( array( "\r", "\n" ), ' ', $value );

		return str_replace( array( '\\', '"' ), array( '\\\\', '\\"' ), $value );
	}
}
