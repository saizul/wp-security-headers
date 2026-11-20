<?php
declare(strict_types=1);

namespace Saizul\SecurityHeaders\Tests\Unit;

use Saizul\SecurityHeaders\Csp\Policy;
use Saizul\SecurityHeaders\Csp\Presets;
use Saizul\SecurityHeaders\Tests\WpTestCase;

final class PolicyTest extends WpTestCase {

	/**
	 * @return array<string,array{0:string,1:?string}>
	 */
	public function sources(): array {
		return array(
			'quoted self'          => array( "'self'", "'self'" ),
			'bare self is quoted'  => array( 'self', "'self'" ),
			'upper case keyword'   => array( "'UNSAFE-INLINE'", "'unsafe-inline'" ),
			'strict-dynamic'       => array( 'strict-dynamic', "'strict-dynamic'" ),
			'none'                 => array( "'none'", "'none'" ),
			'scheme'               => array( 'https:', 'https:' ),
			'data scheme'          => array( 'DATA:', 'data:' ),
			'host'                 => array( 'cdn.example.com', 'cdn.example.com' ),
			'host with scheme'     => array( 'https://cdn.example.com', 'https://cdn.example.com' ),
			'wildcard subdomain'   => array( 'https://*.example.com', 'https://*.example.com' ),
			'port and path'        => array( 'https://example.com:8443/js/', 'https://example.com:8443/js/' ),
			'wildcard port'        => array( 'example.com:*', 'example.com:*' ),
			'host case folded'     => array( 'HTTPS://CDN.Example.COM/Path', 'https://cdn.example.com/Path' ),
			'star'                 => array( '*', '*' ),
			'sha256 hash'          => array( "'sha256-abc123+/=='", "'sha256-abc123+/=='" ),
			'nonce refused'        => array( "'nonce-abc123'", null ),
			'unknown keyword'      => array( "'unsafe-everything'", null ),
			'semicolon injection'  => array( "'self';script-src", null ),
			'comma'                => array( 'a.com,b.com', null ),
			'quote in host'        => array( "exa'mple.com", null ),
			'html'                 => array( '<script>', null ),
			'double quote'         => array( '"self"', null ),
			'empty'                => array( '', null ),
			'leading dash host'    => array( '-bad.example.com', null ),
			'javascript url'       => array( 'javascript:alert(1)', null ),
			'backslash'            => array( 'https://a.com\\b', null ),
		);
	}

	/**
	 * @dataProvider sources
	 */
	public function test_sanitize_source( string $input, ?string $expected ): void {
		$this->assertSame( $expected, Policy::sanitize_source( $input ) );
	}

	public function test_sanitize_sources_dedupes_and_drops_invalid(): void {
		$this->assertSame(
			array( "'self'", 'https://cdn.example.com' ),
			Policy::sanitize_sources( 'script-src', "self 'self'  https://cdn.example.com\n<bad> https://cdn.example.com" )
		);
	}

	public function test_none_is_removed_when_other_sources_exist(): void {
		$this->assertSame( array( "'self'" ), Policy::sanitize_sources( 'img-src', "'none' 'self'" ) );
		$this->assertSame( array( "'none'" ), Policy::sanitize_sources( 'object-src', "'none'" ) );
	}

	public function test_sources_are_capped(): void {
		$many = array();
		for ( $i = 0; $i < 100; $i++ ) {
			$many[] = 'h' . $i . '.example.com';
		}
		$this->assertCount( Policy::MAX_SOURCES, Policy::sanitize_sources( 'img-src', $many ) );
	}

	public function test_special_directive_tokens(): void {
		$this->assertSame( 'https://example.org/wp-json/x?a=1', Policy::sanitize_token( 'report-uri', 'https://example.org/wp-json/x?a=1' ) );
		$this->assertNull( Policy::sanitize_token( 'report-uri', 'javascript:alert(1)' ) );
		$this->assertSame( 'wpsh-csp', Policy::sanitize_token( 'report-to', 'wpsh-csp' ) );
		$this->assertNull( Policy::sanitize_token( 'report-to', 'bad name!' ) );
		$this->assertSame( 'allow-forms', Policy::sanitize_token( 'sandbox', 'ALLOW-FORMS' ) );
		$this->assertNull( Policy::sanitize_token( 'sandbox', 'forms' ) );
		$this->assertSame( "'script'", Policy::sanitize_token( 'require-trusted-types-for', 'script' ) );
		$this->assertSame( "'allow-duplicates'", Policy::sanitize_token( 'trusted-types', 'allow-duplicates' ) );
	}

	public function test_from_array_drops_unknown_directives_and_empty_values(): void {
		$policy = Policy::from_array(
			array(
				'default-src'   => "'self'",
				'SCRIPT-SRC'    => array( 'self', 'https://js.example.com' ),
				'made-up-src'   => "'self'",
				'img-src'       => '<nothing valid>',
				'upgrade-insecure-requests' => true,
			)
		);
		$this->assertSame(
			array(
				'default-src'               => array( "'self'" ),
				'script-src'                => array( "'self'", 'https://js.example.com' ),
				'upgrade-insecure-requests' => array(),
			),
			$policy->to_array()
		);
	}

	public function test_serialize_uses_a_stable_directive_order(): void {
		$policy = Policy::from_array(
			array(
				'object-src'                => "'none'",
				'img-src'                   => "'self' data:",
				'upgrade-insecure-requests' => true,
				'default-src'               => "'self'",
			)
		);
		$this->assertSame( "default-src 'self'; img-src 'self' data:; object-src 'none'; upgrade-insecure-requests", $policy->serialize() );
	}

	public function test_serialize_round_trips_through_parse(): void {
		$policy = Policy::from_array( Presets::get( Presets::WOOCOMMERCE ) );
		$parsed = Policy::parse( $policy->serialize() );
		$this->assertSame( $policy->serialize(), $parsed->serialize() );
		$this->assertEqualsCanonicalizing( array_keys( $policy->to_array() ), array_keys( $parsed->to_array() ) );
	}

	public function test_parse_keeps_first_occurrence_and_lowercases_names(): void {
		$policy = Policy::parse( "  Default-Src 'self' ; script-src a.com; script-src b.com;;" );
		$this->assertSame( array( "'self'" ), $policy->get( 'default-src' ) );
		$this->assertSame( array( 'a.com' ), $policy->get( 'script-src' ) );
	}

	public function test_effective_follows_fallback_chain(): void {
		$policy = Policy::parse( "default-src 'self'; script-src a.com" );
		$this->assertSame( array( 'a.com' ), $policy->effective( 'script-src-elem' ) );
		$this->assertSame( array( "'self'" ), $policy->effective( 'img-src' ) );
		$this->assertSame( array( 'a.com' ), $policy->effective( 'worker-src' ) );
		$this->assertNull( $policy->effective( 'base-uri' ) );
		$this->assertNull( Policy::parse( 'img-src a.com' )->effective( 'script-src' ) );
	}

	public function test_add_starts_from_default_src_and_drops_none(): void {
		$policy = Policy::parse( "default-src 'self'" )->add( 'script-src', array( "'nonce-abc'" ) );
		$this->assertSame( array( "'self'", "'nonce-abc'" ), $policy->get( 'script-src' ) );

		$none = Policy::parse( "script-src 'none'" )->add( 'script-src', array( "'nonce-abc'" ) );
		$this->assertSame( array( "'nonce-abc'" ), $none->get( 'script-src' ) );
	}

	public function test_policy_is_immutable(): void {
		$policy = Policy::parse( "default-src 'self'" );
		$policy->with( 'img-src', array( 'data:' ) );
		$policy->without( 'default-src' );
		$this->assertSame( "default-src 'self'", $policy->serialize() );
	}

	/**
	 * @param string $header Policy.
	 * @return string[]
	 */
	private static function codes( string $header ): array {
		return array_column( Policy::parse( $header )->warnings(), 'code' );
	}

	public function test_warnings_for_a_weak_policy(): void {
		$codes = self::codes( "default-src *; script-src 'self' 'unsafe-inline' 'unsafe-eval' https: http://old.example.com" );
		$this->assertContains( 'unsafe_inline', $codes );
		$this->assertContains( 'unsafe_eval', $codes );
		$this->assertContains( 'broad_script', $codes );
		$this->assertContains( 'object_src', $codes );
		$this->assertContains( 'base_uri', $codes );
		$this->assertContains( 'insecure_source', $codes );
		$this->assertSame( 'high', Policy::parse( "script-src 'unsafe-inline'" )->warnings()[0]['severity'] );
	}

	public function test_nonce_neutralises_unsafe_inline(): void {
		$codes = self::codes( "default-src 'self'; script-src 'nonce-abc' 'unsafe-inline'; object-src 'none'; base-uri 'self'" );
		$this->assertNotContains( 'unsafe_inline', $codes );
		$this->assertSame( array( 'unsafe_inline_ignored' ), $codes );
	}

	public function test_strict_dynamic_makes_https_fallback_acceptable(): void {
		$codes = self::codes( "default-src 'self'; script-src 'nonce-abc' 'strict-dynamic' https: 'unsafe-inline'; object-src 'none'; base-uri 'none'" );
		$this->assertNotContains( 'broad_script', $codes );
		$this->assertNotContains( 'unsafe_inline', $codes );
	}

	public function test_missing_script_restriction(): void {
		$this->assertContains( 'no_script_src', self::codes( 'img-src data:' ) );
	}

	public function test_warnings_are_sorted_by_severity(): void {
		$severities = array_column( Policy::parse( "img-src http://a.com; script-src 'unsafe-eval'" )->warnings(), 'severity' );
		$rank       = array_flip( array( 'high', 'medium', 'low', 'info' ) );
		$ranks      = array_map(
			static function ( $s ) use ( $rank ) {
				return $rank[ $s ];
			},
			$severities
		);
		$sorted = $ranks;
		sort( $sorted );
		$this->assertSame( $sorted, $ranks );
	}
}
