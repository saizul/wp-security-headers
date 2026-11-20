<?php
/**
 * Parses CSP violation reports.
 *
 * @package Saizul\SecurityHeaders
 */

namespace Saizul\SecurityHeaders\Reports;

defined( 'ABSPATH' ) || exit;

/**
 * Accepts both formats browsers send:
 *
 * - `application/csp-report`: `{"csp-report": {"document-uri": ..., ...}}` (report-uri).
 * - `application/reports+json`: `[{"type": "csp-violation", "body": {...}}]` (report-to).
 *
 * Every value is normalised and truncated. Query strings and fragments are
 * removed from URLs so tokens and personal data are not stored.
 */
final class Parser {

	const MAX_BYTES   = 65536;
	const MAX_REPORTS = 20;

	const CONTENT_TYPES = array( 'application/csp-report', 'application/reports+json', 'application/json' );

	/**
	 * Parse a request body.
	 *
	 * @param string $body         Raw body.
	 * @param string $content_type Content-Type header.
	 * @return array<int,array<string,mixed>>|\WP_Error Normalised violations.
	 */
	public static function parse( string $body, string $content_type ) {
		$type = strtolower( trim( explode( ';', $content_type )[0] ) );
		if ( ! in_array( $type, self::CONTENT_TYPES, true ) ) {
			return new \WP_Error( 'security_headers_unsupported_type', 'Unsupported content type.', array( 'status' => 415 ) );
		}
		if ( strlen( $body ) > self::MAX_BYTES ) {
			return new \WP_Error( 'security_headers_too_large', 'Report too large.', array( 'status' => 413 ) );
		}
		$data = json_decode( $body, true );
		if ( ! is_array( $data ) ) {
			return new \WP_Error( 'security_headers_invalid_json', 'Invalid JSON.', array( 'status' => 400 ) );
		}

		$raw = array();
		if ( isset( $data['csp-report'] ) && is_array( $data['csp-report'] ) ) {
			$raw[] = self::from_legacy( $data['csp-report'] );
		} else {
			$list = self::is_list( $data ) ? $data : array( $data );
			foreach ( $list as $item ) {
				if ( is_array( $item ) && isset( $item['type'], $item['body'] ) && 'csp-violation' === $item['type'] && is_array( $item['body'] ) ) {
					$raw[] = self::from_reporting_api( $item['body'] );
				}
				if ( count( $raw ) >= self::MAX_REPORTS ) {
					break;
				}
			}
		}

		$out = array();
		foreach ( $raw as $report ) {
			$clean = self::normalize( $report );
			if ( null !== $clean ) {
				$out[] = $clean;
			}
		}
		if ( array() === $out ) {
			return new \WP_Error( 'security_headers_no_reports', 'No valid CSP violation reports.', array( 'status' => 400 ) );
		}

		return $out;
	}

	/**
	 * Map a report-uri body to the common shape.
	 *
	 * @param array<string,mixed> $r Report.
	 * @return array<string,mixed>
	 */
	private static function from_legacy( array $r ): array {
		return array(
			'document'    => $r['document-uri'] ?? '',
			'blocked'     => $r['blocked-uri'] ?? '',
			'directive'   => $r['effective-directive'] ?? ( $r['violated-directive'] ?? '' ),
			'source_file' => $r['source-file'] ?? '',
			'line'        => $r['line-number'] ?? 0,
			'sample'      => $r['script-sample'] ?? '',
			'disposition' => $r['disposition'] ?? '',
		);
	}

	/**
	 * Map a Reporting API body to the common shape.
	 *
	 * @param array<string,mixed> $r Report body.
	 * @return array<string,mixed>
	 */
	private static function from_reporting_api( array $r ): array {
		return array(
			'document'    => $r['documentURL'] ?? '',
			'blocked'     => $r['blockedURL'] ?? '',
			'directive'   => $r['effectiveDirective'] ?? '',
			'source_file' => $r['sourceFile'] ?? '',
			'line'        => $r['lineNumber'] ?? 0,
			'sample'      => $r['sample'] ?? '',
			'disposition' => $r['disposition'] ?? '',
		);
	}

	/**
	 * Validate and clean one report. Returns null when it is not usable.
	 *
	 * @param array<string,mixed> $r Report in the common shape.
	 * @return array<string,mixed>|null
	 */
	public static function normalize( array $r ): ?array {
		$directive = is_string( $r['directive'] ) ? strtolower( trim( explode( ' ', trim( $r['directive'] ) )[0] ) ) : '';
		if ( ! preg_match( '/^[a-z][a-z-]{2,39}$/', $directive ) ) {
			return null;
		}
		$document = self::url( $r['document'] );
		if ( '' === $document ) {
			return null;
		}
		$disposition = is_string( $r['disposition'] ) ? strtolower( $r['disposition'] ) : '';

		return array(
			'directive'   => $directive,
			'blocked_uri' => self::blocked( $r['blocked'] ),
			'document'    => $document,
			'source_file' => self::url( $r['source_file'] ),
			'line'        => is_numeric( $r['line'] ) ? max( 0, min( 10000000, (int) $r['line'] ) ) : 0,
			'sample'      => self::text( $r['sample'], 256 ),
			'disposition' => in_array( $disposition, array( 'enforce', 'report' ), true ) ? $disposition : '',
		);
	}

	/**
	 * Blocked URI: a keyword (inline, eval, data, ...) or a cleaned URL.
	 *
	 * @param mixed $value Raw value.
	 */
	public static function blocked( $value ): string {
		if ( ! is_string( $value ) ) {
			return '';
		}
		$value = trim( $value );
		$lower = strtolower( $value );
		if ( preg_match( '/^(inline|eval|wasm-eval|self|trusted-types-policy|trusted-types-sink)$/', $lower ) ) {
			return $lower;
		}
		if ( preg_match( '/^(data|blob|filesystem|mediastream|about|chrome-extension|moz-extension|safari-extension|safari-web-extension):?/', $lower, $m ) ) {
			return $m[1];
		}

		return self::url( $value );
	}

	/**
	 * URL without query string, fragment or credentials, at most 512 bytes.
	 * Returns '' for anything that is not an http(s) or ws(s) URL.
	 *
	 * @param mixed $value Raw URL.
	 */
	public static function url( $value ): string {
		if ( ! is_string( $value ) || '' === trim( $value ) ) {
			return '';
		}
		$parts = wp_parse_url( trim( $value ) );
		if ( ! is_array( $parts ) || ! isset( $parts['scheme'], $parts['host'] ) ) {
			return '';
		}
		$scheme = strtolower( $parts['scheme'] );
		if ( ! in_array( $scheme, array( 'http', 'https', 'ws', 'wss' ), true ) ) {
			return '';
		}
		$host = strtolower( $parts['host'] );
		if ( ! preg_match( '/^[a-z0-9.\-\[\]:]+$/', $host ) ) {
			return '';
		}
		$url = $scheme . '://' . $host . ( isset( $parts['port'] ) ? ':' . (int) $parts['port'] : '' ) . ( $parts['path'] ?? '' );

		return self::text( $url, 512 );
	}

	/**
	 * Plain text without control characters, truncated.
	 *
	 * @param mixed $value Raw value.
	 * @param int   $max   Maximum bytes.
	 */
	public static function text( $value, int $max ): string {
		if ( ! is_string( $value ) ) {
			return '';
		}
		$value = (string) preg_replace( '/[\x00-\x1f\x7f]+/', ' ', $value );
		if ( strlen( $value ) > $max ) {
			$value = substr( $value, 0, $max );
			// Do not cut a UTF-8 character in half.
			$tries = 0;
			while ( $tries < 3 && '' !== $value && false === preg_match( '//u', $value ) ) {
				$value = substr( $value, 0, -1 );
				++$tries;
			}
		}

		return trim( $value );
	}

	/**
	 * Whether an array is a list (0..n-1 keys).
	 *
	 * @param array<mixed,mixed> $data Array.
	 */
	private static function is_list( array $data ): bool {
		return array() === $data || array_keys( $data ) === range( 0, count( $data ) - 1 );
	}
}
