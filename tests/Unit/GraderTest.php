<?php
declare(strict_types=1);

namespace Saizul\SecurityHeaders\Tests\Unit;

use Saizul\SecurityHeaders\Grader;
use Saizul\SecurityHeaders\Tests\WpTestCase;

final class GraderTest extends WpTestCase {

	/**
	 * Headers that earn every point.
	 *
	 * @return array<string,string>
	 */
	private static function perfect(): array {
		return array(
			'Strict-Transport-Security'    => 'max-age=63072000; includeSubDomains; preload',
			'Content-Security-Policy'      => "default-src 'self'; script-src 'self' 'nonce-abc'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'",
			'X-Content-Type-Options'       => 'nosniff',
			'Referrer-Policy'              => 'strict-origin-when-cross-origin',
			'Permissions-Policy'           => 'camera=()',
			'Cross-Origin-Opener-Policy'   => 'same-origin',
			'Cross-Origin-Resource-Policy' => 'same-origin',
		);
	}

	/**
	 * @param array<string,mixed> $result Grade result.
	 * @return array<string,array<string,mixed>>
	 */
	private static function by_key( array $result ): array {
		$out = array();
		foreach ( $result['findings'] as $finding ) {
			$out[ $finding['key'] ] = $finding;
		}
		return $out;
	}

	public function test_perfect_headers_get_an_a(): void {
		$result = Grader::grade( self::perfect(), true );
		$this->assertSame( 'A', $result['grade'] );
		$this->assertSame( 100, $result['score'] );
		$this->assertSame( 100, $result['max'] );
		foreach ( $result['findings'] as $finding ) {
			$this->assertSame( 'pass', $finding['status'], $finding['key'] );
			$this->assertSame( '', $finding['fix'] );
		}
	}

	public function test_no_headers_get_an_f_with_fixes(): void {
		$result = Grader::grade( array(), true );
		$this->assertSame( 'F', $result['grade'] );
		$this->assertSame( 5, $result['score'] );
		foreach ( $result['findings'] as $finding ) {
			$this->assertNotSame( 'pass', $finding['status'], $finding['key'] );
			$this->assertNotSame( '', $finding['fix'], $finding['key'] );
		}
	}

	public function test_wordpress_defaults_grade(): void {
		$result = Grader::grade(
			array(
				'X-Content-Type-Options'  => 'nosniff',
				'Referrer-Policy'         => 'strict-origin-when-cross-origin',
				'X-Frame-Options'         => 'SAMEORIGIN',
				'Permissions-Policy'      => 'camera=()',
				'Content-Security-Policy' => "frame-ancestors 'self'",
			),
			true
		);
		// 45 points: framing 15, nosniff 10, referrer 10, permissions 10.
		$this->assertSame( 45, $result['score'] );
		$this->assertSame( 'D', $result['grade'] );
		$this->assertSame( 'fail', self::by_key( $result )['csp']['status'] );
	}

	public function test_letters(): void {
		$this->assertSame( 'A', Grader::letter( 90 ) );
		$this->assertSame( 'B', Grader::letter( 89 ) );
		$this->assertSame( 'C', Grader::letter( 60 ) );
		$this->assertSame( 'D', Grader::letter( 45 ) );
		$this->assertSame( 'E', Grader::letter( 30 ) );
		$this->assertSame( 'F', Grader::letter( 29 ) );
		$this->assertSame( 'F', Grader::letter( -1 ) );
	}

	public function test_report_only_csp_gets_partial_credit(): void {
		$headers = self::perfect();
		unset( $headers['Content-Security-Policy'] );
		$headers['Content-Security-Policy-Report-Only'] = "default-src 'self'";
		$csp = self::by_key( Grader::grade( $headers, true ) )['csp'];
		$this->assertSame( 'warn', $csp['status'] );
		$this->assertSame( 5, $csp['score'] );
	}

	public function test_unsafe_inline_costs_points_unless_neutralised(): void {
		$weak = self::perfect();
		$weak['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'self'";
		$csp = self::by_key( Grader::grade( $weak, true ) )['csp'];
		$this->assertSame( 'warn', $csp['status'] );
		$this->assertSame( 17, $csp['score'] );
		$this->assertStringContainsString( 'unsafe-inline', $csp['fix'] );

		$guarded = self::perfect();
		$guarded['Content-Security-Policy'] = "default-src 'self'; script-src 'nonce-abc' 'unsafe-inline' 'strict-dynamic'; object-src 'none'; base-uri 'none'";
		$this->assertSame( 25, self::by_key( Grader::grade( $guarded, true ) )['csp']['score'] );
	}

	public function test_csp_score_has_a_floor(): void {
		$headers = array( 'Content-Security-Policy' => "default-src * 'unsafe-inline' 'unsafe-eval'" );
		$this->assertSame( 5, self::by_key( Grader::grade( $headers, true ) )['csp']['score'] );
	}

	public function test_frame_ancestors_only_policy_does_not_count_as_csp(): void {
		$result = self::by_key( Grader::grade( array( 'Content-Security-Policy' => "frame-ancestors 'none'" ), true ) );
		$this->assertSame( 0, $result['csp']['score'] );
		$this->assertSame( 15, $result['framing']['score'] );
	}

	public function test_multiple_policies_joined_with_commas(): void {
		$result = self::by_key( Grader::grade( array( 'content-security-policy' => array( "frame-ancestors 'self', default-src 'self'; object-src 'none'; base-uri 'self'" ) ), true ) );
		$this->assertSame( 'pass', $result['csp']['status'] );
		$this->assertSame( 'pass', $result['framing']['status'] );
	}

	public function test_hsts_rules(): void {
		$short = self::by_key( Grader::grade( array( 'Strict-Transport-Security' => 'max-age=300' ), true ) )['hsts'];
		$this->assertSame( 10, $short['score'] );
		$zero = self::by_key( Grader::grade( array( 'Strict-Transport-Security' => 'max-age=0' ), true ) )['hsts'];
		$this->assertSame( 0, $zero['score'] );
		$http = self::by_key( Grader::grade( self::perfect(), false ) )['hsts'];
		$this->assertSame( 'fail', $http['status'] );
		$this->assertSame( 0, $http['score'] );
		$this->assertSame( 'B', Grader::grade( self::perfect(), false )['grade'] );
	}

	public function test_obsolete_x_frame_options(): void {
		$framing = self::by_key( Grader::grade( array( 'X-Frame-Options' => 'ALLOW-FROM https://a.example' ), true ) )['framing'];
		$this->assertSame( 0, $framing['score'] );
		$this->assertStringContainsString( 'ALLOW-FROM', $framing['message'] );
		$this->assertSame( 15, self::by_key( Grader::grade( array( 'x-frame-options' => 'deny' ), true ) )['framing']['score'] );
	}

	public function test_referrer_policy_values(): void {
		$score = static function ( string $value ): int {
			return self::by_key( Grader::grade( array( 'Referrer-Policy' => $value ), true ) )['referrer']['score'];
		};
		$this->assertSame( 10, $score( 'no-referrer' ) );
		$this->assertSame( 7, $score( 'origin-when-cross-origin' ) );
		$this->assertSame( 0, $score( 'unsafe-url' ) );
		$this->assertSame( 0, $score( 'no-referrer-when-downgrade' ) );
		// Browsers use the last value they understand.
		$this->assertSame( 10, $score( 'unsafe-url, strict-origin, made-up' ) );
		$this->assertSame( 5, self::by_key( Grader::grade( array(), true ) )['referrer']['score'] );
	}

	public function test_legacy_feature_policy(): void {
		$this->assertSame( 5, self::by_key( Grader::grade( array( 'Feature-Policy' => "camera 'none'" ), true ) )['permissions']['score'] );
	}

	public function test_cross_origin_resource_policy_cross_origin_is_partial(): void {
		$this->assertSame( 3, self::by_key( Grader::grade( array( 'Cross-Origin-Resource-Policy' => 'cross-origin' ), true ) )['corp']['score'] );
	}

	public function test_information_leaks_are_reported_without_cost(): void {
		$headers                     = self::perfect();
		$headers['X-Powered-By']     = 'PHP/8.3.1';
		$headers['Server']           = 'nginx/1.25.3';
		$headers['X-XSS-Protection'] = '1; mode=block';
		$result                      = Grader::grade( $headers, true );
		$findings                    = self::by_key( $result );
		$this->assertSame( 'info', $findings['x_powered_by']['status'] );
		$this->assertSame( 'info', $findings['server']['status'] );
		$this->assertSame( 'info', $findings['x_xss_protection']['status'] );
		$this->assertSame( 100, $result['score'] );
		$this->assertArrayNotHasKey( 'server', self::by_key( Grader::grade( array( 'Server' => 'nginx' ), true ) ) );
	}

	public function test_normalize(): void {
		$this->assertSame(
			array(
				'x-a'                     => array( '1', '2' ),
				'content-security-policy' => array( "default-src 'self'", "img-src 'self'" ),
			),
			Grader::normalize(
				array(
					'X-A'                     => array( ' 1', '2 ' ),
					'Content-Security-Policy' => "default-src 'self', img-src 'self'",
				)
			)
		);
	}

	public function test_duplicate_headers_joined_by_a_proxy_still_pass(): void {
		$headers                              = self::perfect();
		$headers['X-Content-Type-Options']    = 'nosniff, nosniff';
		$headers['Strict-Transport-Security'] = array( 'max-age=63072000; includeSubDomains; preload', 'max-age=31536000' );
		$result                               = Grader::grade( $headers, true );
		$found                                = self::by_key( $result );

		$this->assertSame( 'pass', $found['nosniff']['status'] );
		$this->assertSame( 'pass', $found['hsts']['status'], 'browsers use the first HSTS header' );
		$this->assertSame( 100, $result['score'] );
		$this->assertSame( 'info', $found['duplicate_x_content_type_options']['status'] );
		$this->assertStringContainsString( 'X-Content-Type-Options is sent 2 times with the same value', $found['duplicate_x_content_type_options']['message'] );
		$this->assertStringContainsString( 'different values', $found['duplicate_strict_transport_security']['message'] );
		$this->assertNotSame( '', $found['duplicate_strict_transport_security']['fix'] );
	}

	public function test_conflicting_x_frame_options_fail_unless_frame_ancestors(): void {
		$headers = array( 'X-Frame-Options' => 'SAMEORIGIN, DENY' );
		$found   = self::by_key( Grader::grade( $headers, true ) );
		$this->assertSame( 'fail', $found['framing']['status'] );
		$this->assertStringContainsString( 'conflicting values (SAMEORIGIN, DENY)', $found['framing']['message'] );
		$this->assertArrayHasKey( 'duplicate_x_frame_options', $found );

		$same = self::by_key( Grader::grade( array( 'X-Frame-Options' => array( 'SAMEORIGIN', 'sameorigin' ) ), true ) );
		$this->assertSame( 'pass', $same['framing']['status'] );
		$this->assertStringContainsString( 'same value', $same['duplicate_x_frame_options']['message'] );

		$headers['Content-Security-Policy'] = "frame-ancestors 'self'";
		$this->assertSame( 'pass', self::by_key( Grader::grade( $headers, true ) )['framing']['status'] );
	}

	public function test_single_headers_do_not_report_duplicates(): void {
		foreach ( Grader::grade( self::perfect(), true )['findings'] as $finding ) {
			$this->assertStringStartsNotWith( 'duplicate_', $finding['key'] );
		}
	}
}
