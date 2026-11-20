<?php
/**
 * Builds the list of headers from the settings.
 *
 * @package Saizul\SecurityHeaders
 */

namespace Saizul\SecurityHeaders;

use Saizul\SecurityHeaders\Csp\Policy;

defined( 'ABSPATH' ) || exit;

/**
 * Pure function of settings and a request context. No headers are sent here.
 */
final class HeaderBuilder {

	const AREA_FRONT = 'front';
	const AREA_ADMIN = 'admin';
	const AREA_LOGIN = 'login';

	const REPORT_GROUP = 'wpsh-csp';

	/**
	 * Headers for a request.
	 *
	 * Context keys:
	 * - `area`: front, admin or login.
	 * - `https`: whether the request is served over HTTPS.
	 * - `nonce`: per-request CSP nonce, or null.
	 * - `report_url`: absolute URL of the report endpoint, or ''.
	 *
	 * @param array<string,mixed> $settings Settings.
	 * @param array<string,mixed> $context  Context.
	 * @return array<int,array{0:string,1:string}> Name, value pairs.
	 */
	public static function build( array $settings, array $context ): array {
		$area    = (string) ( $context['area'] ?? self::AREA_FRONT );
		$https   = ! empty( $context['https'] );
		$headers = array();

		if ( ! empty( $settings['hsts_enabled'] ) && $https ) {
			$headers[] = array( 'Strict-Transport-Security', Hsts::value( $settings ) );
		}
		if ( ! empty( $settings['nosniff'] ) ) {
			$headers[] = array( 'X-Content-Type-Options', 'nosniff' );
		}
		if ( '' !== (string) $settings['referrer_policy'] ) {
			$headers[] = array( 'Referrer-Policy', (string) $settings['referrer_policy'] );
		}
		if ( 'deny' === $settings['framing'] ) {
			$headers[] = array( 'X-Frame-Options', 'DENY' );
		} elseif ( 'sameorigin' === $settings['framing'] ) {
			$headers[] = array( 'X-Frame-Options', 'SAMEORIGIN' );
		}

		$permissions = PermissionsPolicy::serialize( (array) $settings['permissions'] );
		if ( '' !== $permissions ) {
			$headers[] = array( 'Permissions-Policy', $permissions );
		}
		if ( '' !== (string) $settings['coop'] ) {
			$headers[] = array( 'Cross-Origin-Opener-Policy', (string) $settings['coop'] );
		}
		if ( '' !== (string) $settings['corp'] ) {
			$headers[] = array( 'Cross-Origin-Resource-Policy', (string) $settings['corp'] );
		}

		$ancestors = self::frame_ancestors( $settings );
		$mode      = (string) $settings['csp_mode'];
		$csp_here  = self::AREA_FRONT === $area && Settings::CSP_OFF !== $mode;

		if ( $csp_here ) {
			$report_url = (string) ( $context['report_url'] ?? '' );
			$nonce      = isset( $context['nonce'] ) ? (string) $context['nonce'] : null;
			$policy     = self::csp( $settings, $nonce, $report_url );

			if ( Settings::CSP_ENFORCE === $mode ) {
				if ( null !== $ancestors ) {
					$policy = $policy->with( 'frame-ancestors', $ancestors );
				}
				if ( ! $policy->is_empty() ) {
					$headers[] = array( 'Content-Security-Policy', $policy->serialize() );
				}
			} else {
				// frame-ancestors is ignored in Report-Only, so it stays enforced on its own.
				if ( null !== $ancestors ) {
					$headers[] = array( 'Content-Security-Policy', 'frame-ancestors ' . implode( ' ', $ancestors ) );
				}
				if ( ! $policy->is_empty() ) {
					$headers[] = array( 'Content-Security-Policy-Report-Only', $policy->without( 'upgrade-insecure-requests' )->serialize() );
				}
			}
			if ( ! empty( $settings['csp_report'] ) && '' !== $report_url ) {
				$headers[] = array( 'Reporting-Endpoints', self::REPORT_GROUP . '="' . $report_url . '"' );
			}
		} elseif ( null !== $ancestors ) {
			$headers[] = array( 'Content-Security-Policy', 'frame-ancestors ' . implode( ' ', $ancestors ) );
		}

		return $headers;
	}

	/**
	 * The CSP built from the directives, the nonce and the reporting options.
	 *
	 * @param array<string,mixed> $settings   Settings.
	 * @param string|null         $nonce      Nonce (base64), or null.
	 * @param string              $report_url Report endpoint URL, or ''.
	 */
	public static function csp( array $settings, ?string $nonce, string $report_url = '' ): Policy {
		$policy = Policy::from_array( (array) $settings['csp_directives'] );

		if ( ! empty( $settings['csp_nonce'] ) && null !== $nonce && preg_match( '/^[A-Za-z0-9+\/=_-]{16,128}$/', $nonce ) ) {
			$policy = $policy->add( 'script-src', array( "'nonce-" . $nonce . "'" ) );
		}
		if ( ! empty( $settings['csp_upgrade_insecure'] ) ) {
			$policy = $policy->with( 'upgrade-insecure-requests', array() );
		}
		if ( ! empty( $settings['csp_report'] ) && '' !== $report_url && null !== Policy::sanitize_token( 'report-uri', $report_url ) ) {
			$policy = $policy->with( 'report-uri', array( $report_url ) )->with( 'report-to', array( self::REPORT_GROUP ) );
		}

		return $policy;
	}

	/**
	 * Sources for frame-ancestors, or null when framing is not restricted.
	 *
	 * @param array<string,mixed> $settings Settings.
	 * @return string[]|null
	 */
	public static function frame_ancestors( array $settings ): ?array {
		if ( 'deny' === $settings['framing'] ) {
			return array( "'none'" );
		}
		if ( 'sameorigin' === $settings['framing'] ) {
			return array_merge( array( "'self'" ), (array) $settings['frame_ancestors'] );
		}

		return null;
	}
}
