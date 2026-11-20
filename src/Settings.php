<?php
/**
 * Stored settings.
 *
 * @package Saizul\SecurityHeaders
 */

namespace Saizul\SecurityHeaders;

use Saizul\SecurityHeaders\Csp\Presets;

defined( 'ABSPATH' ) || exit;

/**
 * One option row per site holds every setting.
 */
final class Settings {

	const OPTION = 'wp_security_headers_settings';

	const CSP_OFF         = 'off';
	const CSP_REPORT_ONLY = 'report-only';
	const CSP_ENFORCE     = 'enforce';

	/**
	 * Default values. Nothing that can break a site is on by default: HSTS,
	 * CSP and the cross-origin headers start switched off.
	 *
	 * @return array<string,mixed>
	 */
	public static function defaults(): array {
		return array(
			'hsts_enabled'            => false,
			'hsts_max_age'            => 31536000,
			'hsts_include_subdomains' => false,
			'hsts_preload'            => false,
			'nosniff'                 => true,
			'referrer_policy'         => 'strict-origin-when-cross-origin',
			'framing'                 => 'sameorigin',
			'frame_ancestors'         => array(),
			'coop'                    => '',
			'corp'                    => '',
			'permissions'             => PermissionsPolicy::defaults(),
			'csp_mode'                => self::CSP_OFF,
			'csp_preset'              => Presets::WORDPRESS,
			'csp_directives'          => Presets::get( Presets::WORDPRESS ),
			'csp_nonce'               => false,
			'csp_upgrade_insecure'    => true,
			'csp_report'              => true,
			'report_cap'              => 1000,
			'report_rate_limit'       => 30,
			'apply_admin'             => false,
			'apply_login'             => false,
			'remove_powered_by'       => true,
		);
	}

	/**
	 * Current settings, merged with the defaults.
	 *
	 * @return array<string,mixed>
	 */
	public static function get(): array {
		$stored = get_option( self::OPTION, array() );
		if ( ! is_array( $stored ) ) {
			$stored = array();
		}

		return array_merge( self::defaults(), array_intersect_key( $stored, self::defaults() ) );
	}

	/**
	 * Store settings that have already been sanitised.
	 *
	 * @param array<string,mixed> $settings Settings.
	 */
	public static function save( array $settings ): void {
		update_option( self::OPTION, array_merge( self::defaults(), array_intersect_key( $settings, self::defaults() ) ) );
	}

	/**
	 * Sanitise raw input from the settings form.
	 *
	 * @param mixed $input Raw input.
	 * @return array<string,mixed>
	 */
	public static function sanitize( $input ): array {
		return Sanitizer::sanitize( $input, self::get() );
	}
}
