<?php
declare(strict_types=1);

namespace Saizul\SecurityHeaders\Tests\Unit;

use Saizul\SecurityHeaders\Csp\Presets;
use Saizul\SecurityHeaders\HeaderBuilder;
use Saizul\SecurityHeaders\Hsts;
use Saizul\SecurityHeaders\PermissionsPolicy;
use Saizul\SecurityHeaders\Settings;
use Saizul\SecurityHeaders\Tests\WpTestCase;

final class HeaderBuilderTest extends WpTestCase {

	const NONCE  = 'AAAAAAAAAAAAAAAAAAAAAA==';
	const REPORT = 'https://example.org/wp-json/security-headers/v1/report';

	/**
	 * @param array<string,mixed> $settings Overrides.
	 * @param array<string,mixed> $context  Overrides.
	 * @return array<int,array{0:string,1:string}>
	 */
	private static function build( array $settings = array(), array $context = array() ): array {
		return HeaderBuilder::build(
			self::settings( $settings ),
			array_merge(
				array(
					'area'       => 'front',
					'https'      => true,
					'nonce'      => self::NONCE,
					'report_url' => self::REPORT,
				),
				$context
			)
		);
	}

	public function test_defaults_are_safe_to_activate(): void {
		$this->assertSame(
			array(
				array( 'X-Content-Type-Options', 'nosniff' ),
				array( 'Referrer-Policy', 'strict-origin-when-cross-origin' ),
				array( 'X-Frame-Options', 'SAMEORIGIN' ),
				array( 'Permissions-Policy', 'browsing-topics=(), camera=(), display-capture=(), geolocation=(), hid=(), microphone=(), midi=(), serial=(), usb=()' ),
				array( 'Content-Security-Policy', "frame-ancestors 'self'" ),
			),
			self::build()
		);
	}

	public function test_hsts_is_only_sent_over_https(): void {
		$on = array( 'hsts_enabled' => true );
		$this->assertArrayHasKey( 'Strict-Transport-Security', self::map( self::build( $on ) ) );
		$this->assertArrayNotHasKey( 'Strict-Transport-Security', self::map( self::build( $on, array( 'https' => false ) ) ) );
		$this->assertArrayNotHasKey( 'Strict-Transport-Security', self::map( self::build() ) );
	}

	public function test_hsts_value(): void {
		$this->assertSame( 'max-age=300', Hsts::value( self::settings( array( 'hsts_max_age' => 300 ) ) ) );
		$this->assertSame(
			'max-age=63072000; includeSubDomains; preload',
			Hsts::value(
				self::settings(
					array(
						'hsts_max_age'            => 63072000,
						'hsts_include_subdomains' => true,
						'hsts_preload'            => true,
					)
				)
			)
		);
	}

	public function test_headers_can_be_switched_off(): void {
		$headers = self::build(
			array(
				'nosniff'         => false,
				'referrer_policy' => '',
				'framing'         => 'off',
				'permissions'     => array(),
			)
		);
		$this->assertSame( array(), $headers );
	}

	public function test_deny_framing(): void {
		$map = self::map( self::build( array( 'framing' => 'deny' ) ) );
		$this->assertSame( 'DENY', $map['X-Frame-Options'] );
		$this->assertSame( "frame-ancestors 'none'", $map['Content-Security-Policy'] );
	}

	public function test_extra_framing_origins(): void {
		$map = self::map( self::build( array( 'frame_ancestors' => array( 'https://partner.example' ) ) ) );
		$this->assertSame( "frame-ancestors 'self' https://partner.example", $map['Content-Security-Policy'] );
	}

	public function test_permissions_policy_serialization(): void {
		$this->assertSame(
			'camera=(), fullscreen=(self), geolocation=()',
			PermissionsPolicy::serialize(
				array(
					'geolocation' => 'none',
					'fullscreen'  => 'self',
					'camera'      => 'none',
					'made-up'     => 'none',
					'usb'         => 'everyone',
				)
			)
		);
	}

	public function test_cross_origin_headers(): void {
		$map = self::map(
			self::build(
				array(
					'coop' => 'same-origin-allow-popups',
					'corp' => 'same-site',
				)
			)
		);
		$this->assertSame( 'same-origin-allow-popups', $map['Cross-Origin-Opener-Policy'] );
		$this->assertSame( 'same-site', $map['Cross-Origin-Resource-Policy'] );
	}

	public function test_enforced_csp_merges_frame_ancestors_and_reporting(): void {
		$map = self::map(
			self::build(
				array(
					'csp_mode'       => Settings::CSP_ENFORCE,
					'csp_directives' => array(
						'default-src' => array( "'self'" ),
						'object-src'  => array( "'none'" ),
					),
				)
			)
		);
		$this->assertSame(
			"default-src 'self'; object-src 'none'; frame-ancestors 'self'; upgrade-insecure-requests; report-uri " . self::REPORT . '; report-to wpsh-csp',
			$map['Content-Security-Policy']
		);
		$this->assertSame( 'wpsh-csp="' . self::REPORT . '"', $map['Reporting-Endpoints'] );
		$this->assertArrayNotHasKey( 'Content-Security-Policy-Report-Only', $map );
	}

	public function test_report_only_keeps_frame_ancestors_enforced(): void {
		$headers = self::build(
			array(
				'csp_mode'       => Settings::CSP_REPORT_ONLY,
				'csp_directives' => array( 'default-src' => array( "'self'" ) ),
			)
		);
		$map = self::map( $headers );
		$this->assertSame( "frame-ancestors 'self'", $map['Content-Security-Policy'] );
		$this->assertSame( "default-src 'self'; report-uri " . self::REPORT . '; report-to wpsh-csp', $map['Content-Security-Policy-Report-Only'] );
		$this->assertStringNotContainsString( 'upgrade-insecure-requests', $map['Content-Security-Policy-Report-Only'] );
	}

	public function test_nonce_is_added_to_script_src(): void {
		$map = self::map(
			self::build(
				array(
					'csp_mode'       => Settings::CSP_ENFORCE,
					'csp_nonce'      => true,
					'csp_report'     => false,
					'framing'        => 'off',
					'csp_directives' => array(
						'default-src' => array( "'self'" ),
						'script-src'  => array( "'self'" ),
					),
				)
			)
		);
		$this->assertSame( "default-src 'self'; script-src 'self' 'nonce-" . self::NONCE . "'; upgrade-insecure-requests", $map['Content-Security-Policy'] );
		$this->assertArrayNotHasKey( 'Reporting-Endpoints', $map );
	}

	public function test_nonce_without_script_src_copies_default_src(): void {
		$policy = HeaderBuilder::csp(
			self::settings(
				array(
					'csp_nonce'            => true,
					'csp_upgrade_insecure' => false,
					'csp_directives'       => array( 'default-src' => array( "'self'" ) ),
				)
			),
			self::NONCE
		);
		$this->assertSame( "default-src 'self'; script-src 'self' 'nonce-" . self::NONCE . "'", $policy->serialize() );
	}

	public function test_malformed_nonce_is_ignored(): void {
		$policy = HeaderBuilder::csp( self::settings( array( 'csp_nonce' => true ) ), "abc'; script-src *" );
		$this->assertStringNotContainsString( 'nonce-', $policy->serialize() );
	}

	public function test_strict_preset_with_nonce(): void {
		$value = HeaderBuilder::csp(
			self::settings(
				array(
					'csp_nonce'      => true,
					'csp_directives' => Presets::get( Presets::STRICT ),
				)
			),
			self::NONCE
		)->serialize();
		$this->assertStringContainsString( "script-src 'strict-dynamic' https: 'unsafe-inline' 'nonce-" . self::NONCE . "'", $value );
		$this->assertStringContainsString( "object-src 'none'", $value );
		$this->assertStringContainsString( "base-uri 'none'", $value );
	}

	public function test_csp_is_front_end_only(): void {
		$settings = array(
			'csp_mode'    => Settings::CSP_ENFORCE,
			'apply_admin' => true,
		);
		foreach ( array( 'admin', 'login' ) as $area ) {
			$map = self::map( self::build( $settings, array( 'area' => $area ) ) );
			$this->assertSame( "frame-ancestors 'self'", $map['Content-Security-Policy'], $area );
			$this->assertArrayNotHasKey( 'Reporting-Endpoints', $map, $area );
			$this->assertSame( 'nosniff', $map['X-Content-Type-Options'], $area );
		}
	}

	public function test_empty_policy_is_not_sent(): void {
		$map = self::map(
			self::build(
				array(
					'csp_mode'             => Settings::CSP_REPORT_ONLY,
					'csp_directives'       => array(),
					'csp_upgrade_insecure' => false,
					'csp_report'           => false,
				)
			)
		);
		$this->assertArrayNotHasKey( 'Content-Security-Policy-Report-Only', $map );
	}

	public function test_presets_produce_valid_policies(): void {
		foreach ( Presets::slugs() as $slug ) {
			$value = HeaderBuilder::csp( self::settings( array( 'csp_directives' => Presets::get( $slug ) ) ), null )->serialize();
			$this->assertStringContainsString( "default-src 'self'", $value, $slug );
			$this->assertStringContainsString( "object-src 'none'", $value, $slug );
		}
		$woo = Presets::get( Presets::WOOCOMMERCE );
		$this->assertContains( 'https://js.stripe.com', $woo['script-src'] );
		$this->assertContains( 'https://hooks.stripe.com', $woo['frame-src'] );
		$this->assertContains( 'https://api.stripe.com', $woo['connect-src'] );
		$this->assertSame( Presets::get( Presets::WORDPRESS ), Presets::get( 'unknown' ) );
		$this->assertTrue( Presets::needs_nonce( Presets::STRICT ) );
		$this->assertFalse( Presets::needs_nonce( Presets::WORDPRESS ) );
	}
}
