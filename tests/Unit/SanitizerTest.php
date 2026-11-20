<?php
declare(strict_types=1);

namespace Saizul\SecurityHeaders\Tests\Unit;

use Saizul\SecurityHeaders\Csp\Presets;
use Saizul\SecurityHeaders\Hsts;
use Saizul\SecurityHeaders\Sanitizer;
use Saizul\SecurityHeaders\Settings;
use Saizul\SecurityHeaders\Tests\WpTestCase;
use WpStubs;

final class SanitizerTest extends WpTestCase {

	/**
	 * @param array<string,mixed> $input Input.
	 * @return array<string,mixed>
	 */
	private static function clean( array $input ): array {
		return Sanitizer::sanitize( $input, Settings::defaults() );
	}

	public function test_non_array_input_keeps_current_settings(): void {
		$current = self::settings( array( 'nosniff' => false ) );
		$this->assertSame( $current, Sanitizer::sanitize( 'garbage', $current ) );
	}

	public function test_output_has_exactly_the_setting_keys(): void {
		$out = self::clean( array( 'evil' => 'x' ) );
		$this->assertSame( array(), array_diff( array_keys( $out ), array_keys( Settings::defaults() ) ) );
		$this->assertSame( array(), array_diff( array_keys( Settings::defaults() ), array_keys( $out ) ) );
	}

	public function test_unchecked_checkboxes_become_false(): void {
		$out = self::clean( array( 'nosniff' => '1' ) );
		$this->assertTrue( $out['nosniff'] );
		$this->assertFalse( $out['hsts_enabled'] );
		$this->assertFalse( $out['remove_powered_by'] );
		$this->assertFalse( Sanitizer::bool( 'no' ) );
		$this->assertTrue( Sanitizer::bool( 'on' ) );
	}

	public function test_enums_fall_back_to_safe_values(): void {
		$out = self::clean(
			array(
				'referrer_policy' => 'leak-everything',
				'framing'         => 'ALLOW-FROM https://x',
				'coop'            => 'same-origin; evil',
				'corp'            => 'SAME-SITE',
				'csp_mode'        => 'block-all',
				'csp_preset'      => 'nope',
			)
		);
		$this->assertSame( '', $out['referrer_policy'] );
		$this->assertSame( 'off', $out['framing'] );
		$this->assertSame( '', $out['coop'] );
		$this->assertSame( 'same-site', $out['corp'] );
		$this->assertSame( Settings::CSP_OFF, $out['csp_mode'] );
		$this->assertSame( Presets::WORDPRESS, $out['csp_preset'] );
	}

	public function test_numbers_are_clamped(): void {
		$out = self::clean(
			array(
				'hsts_max_age'      => '999999999',
				'report_cap'        => '5',
				'report_rate_limit' => 'abc',
			)
		);
		$this->assertSame( Sanitizer::MAX_HSTS_AGE, $out['hsts_max_age'] );
		$this->assertSame( 50, $out['report_cap'] );
		$this->assertSame( 1, $out['report_rate_limit'] );
		$this->assertSame( 0, self::clean( array( 'hsts_max_age' => '-5' ) )['hsts_max_age'] );
	}

	public function test_preload_forces_its_requirements(): void {
		$out = self::clean(
			array(
				'hsts_enabled' => '1',
				'hsts_preload' => '1',
				'hsts_max_age' => '300',
			)
		);
		$this->assertTrue( $out['hsts_include_subdomains'] );
		$this->assertSame( Hsts::ONE_YEAR, $out['hsts_max_age'] );
	}

	public function test_csp_directives_are_sanitised(): void {
		$out = self::clean(
			array(
				'csp_directives' => array(
					'default-src'     => "self",
					'script-src'      => "'self' https://js.example.com 'nonce-fixed' <evil>",
					'img-src'         => '',
					'frame-ancestors' => '*',
					'unknown-src'     => "'self'",
					'style-src'       => array( 'not', 'a', 'string;' ),
				),
			)
		);
		$this->assertSame(
			array(
				'default-src' => array( "'self'" ),
				'script-src'  => array( "'self'", 'https://js.example.com' ),
				'style-src'   => array( 'not', 'a' ),
			),
			$out['csp_directives']
		);
	}

	public function test_slashes_from_the_form_are_removed(): void {
		$out = self::clean( array( 'csp_directives' => array( 'script-src' => "\\'self\\'" ) ) );
		$this->assertSame( array( "'self'" ), $out['csp_directives']['script-src'] );
	}

	public function test_apply_preset_replaces_directives_and_enables_nonce_for_strict(): void {
		$out = self::clean(
			array(
				'csp_preset'     => Presets::STRICT,
				'apply_preset'   => '1',
				'csp_directives' => array( 'default-src' => '*' ),
			)
		);
		$this->assertSame( Presets::get( Presets::STRICT ), $out['csp_directives'] );
		$this->assertTrue( $out['csp_nonce'] );

		$woo = self::clean(
			array(
				'csp_preset'   => Presets::WOOCOMMERCE,
				'apply_preset' => '1',
			)
		);
		$this->assertSame( Presets::get( Presets::WOOCOMMERCE ), $woo['csp_directives'] );
		$this->assertFalse( $woo['csp_nonce'] );
	}

	public function test_permissions_from_the_form_and_from_storage(): void {
		$form = self::clean(
			array(
				'permissions' => array(
					'camera'     => array( 'on' => '1', 'allow' => 'none' ),
					'fullscreen' => array( 'on' => '1', 'allow' => 'self' ),
					'usb'        => array( 'allow' => 'none' ),
					'payment'    => array( 'on' => '1', 'allow' => '*' ),
					'bogus'      => array( 'on' => '1' ),
				),
			)
		);
		$this->assertSame(
			array(
				'camera'     => 'none',
				'fullscreen' => 'self',
				'payment'    => 'none',
			),
			$form['permissions']
		);
		$stored = self::clean( array( 'permissions' => $form['permissions'] ) );
		$this->assertSame( $form['permissions'], $stored['permissions'] );
	}

	public function test_frame_ancestor_origins(): void {
		$out = self::clean( array( 'frame_ancestors' => "https://partner.example\n'self'\n*\nhttps:\njavascript:x\nhttps://*.cdn.example, https://partner.example" ) );
		$this->assertSame( array( 'https://partner.example', 'https://*.cdn.example' ), $out['frame_ancestors'] );
	}

	public function test_sanitising_stored_settings_is_idempotent(): void {
		$once  = self::clean(
			array(
				'hsts_enabled'    => '1',
				'nosniff'         => '1',
				'referrer_policy' => 'no-referrer',
				'framing'         => 'deny',
				'csp_mode'        => 'enforce',
				'csp_directives'  => array( 'default-src' => "'self'" ),
				'frame_ancestors' => 'https://a.example',
			)
		);
		$twice = Sanitizer::sanitize( $once, $once );
		$this->assertSame( $once, $twice );
	}

	public function test_settings_get_merges_defaults_and_ignores_unknown_keys(): void {
		WpStubs::$options[ Settings::OPTION ] = array(
			'nosniff' => false,
			'rogue'   => 1,
		);
		$settings = Settings::get();
		$this->assertFalse( $settings['nosniff'] );
		$this->assertArrayNotHasKey( 'rogue', $settings );
		$this->assertSame( Settings::defaults()['csp_directives'], $settings['csp_directives'] );

		WpStubs::$options[ Settings::OPTION ] = 'corrupt';
		$this->assertSame( Settings::defaults(), Settings::get() );
	}

	public function test_hsts_warnings(): void {
		$this->assertSame( array(), Hsts::warnings( self::settings(), 'https://example.org/' ) );

		$http = Hsts::warnings( self::settings( array( 'hsts_enabled' => true ) ), 'http://example.org/' );
		$this->assertSame( 'high', $http[0]['severity'] );
		$this->assertStringContainsString( 'https://', $http[0]['message'] );

		$preload = Hsts::warnings(
			self::settings(
				array(
					'hsts_enabled'            => true,
					'hsts_preload'            => true,
					'hsts_include_subdomains' => false,
					'hsts_max_age'            => 86400,
				)
			),
			'https://www.example.org/'
		);
		$text = implode( "\n", array_column( $preload, 'message' ) );
		$this->assertStringContainsString( '31536000', $text );
		$this->assertStringContainsString( 'requires includeSubDomains', $text );
		$this->assertStringContainsString( 'www.example.org', $text );
		$this->assertStringContainsString( 'redirect', $text );
		$this->assertStringContainsString( 'hstspreload.org', $text );

		$ok = Hsts::warnings(
			self::settings(
				array(
					'hsts_enabled'            => true,
					'hsts_preload'            => true,
					'hsts_include_subdomains' => true,
					'hsts_max_age'            => 63072000,
				)
			),
			'https://example.org/'
		);
		$text = implode( "\n", array_column( $ok, 'message' ) );
		$this->assertStringNotContainsString( '31536000', $text );
		$this->assertStringNotContainsString( 'registrable domain', $text );
	}
}
