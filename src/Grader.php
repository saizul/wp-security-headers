<?php
/**
 * Grades a set of response headers from A to F.
 *
 * @package Saizul\SecurityHeaders
 */

namespace Saizul\SecurityHeaders;

use Saizul\SecurityHeaders\Csp\Policy;

defined( 'ABSPATH' ) || exit;

/**
 * Scores the security headers of a response and explains how to fix each gap.
 *
 * Points: Content-Security-Policy 25, Strict-Transport-Security 20, framing
 * protection 15, X-Content-Type-Options 10, Referrer-Policy 10,
 * Permissions-Policy 10, Cross-Origin-Opener-Policy 5,
 * Cross-Origin-Resource-Policy 5. Information leaks and duplicate headers
 * (the same single-value header sent twice, e.g. by the plugin and by the
 * web server or CDN) are reported but do not cost points. Conflicting
 * X-Frame-Options values make browsers ignore the header, so they fail the
 * framing check.
 */
final class Grader {

	const PASS = 'pass';
	const WARN = 'warn';
	const FAIL = 'fail';
	const INFO = 'info';

	/**
	 * Headers that take one value. Proxies join repeated headers with commas,
	 * so a comma here means the header was sent more than once.
	 */
	const SINGLE_VALUE = array(
		'strict-transport-security',
		'x-frame-options',
		'x-content-type-options',
		'cross-origin-opener-policy',
		'cross-origin-resource-policy',
	);

	/**
	 * Grade thresholds (minimum score).
	 */
	const GRADES = array(
		'A' => 90,
		'B' => 75,
		'C' => 60,
		'D' => 45,
		'E' => 30,
		'F' => 0,
	);

	/**
	 * Grade headers.
	 *
	 * @param array<string,string|string[]> $headers Response headers (any case).
	 * @param bool                          $https   Whether the response came over HTTPS.
	 * @return array{grade:string,score:int,max:int,findings:array<int,array<string,mixed>>}
	 */
	public static function grade( array $headers, bool $https ): array {
		$h        = self::normalize( $headers );
		$findings = array(
			self::csp( $h ),
			self::hsts( $h, $https ),
			self::framing( $h ),
			self::nosniff( $h ),
			self::referrer( $h ),
			self::permissions( $h ),
			self::coop( $h ),
			self::corp( $h ),
		);
		foreach ( self::leaks( $h ) as $leak ) {
			$findings[] = $leak;
		}
		foreach ( self::duplicates( $h ) as $duplicate ) {
			$findings[] = $duplicate;
		}

		$score = 0;
		$max   = 0;
		foreach ( $findings as $finding ) {
			$score += $finding['score'];
			$max   += $finding['max'];
		}

		return array(
			'grade'    => self::letter( $max > 0 ? (int) round( 100 * $score / $max ) : 0 ),
			'score'    => $score,
			'max'      => $max,
			'findings' => $findings,
		);
	}

	/**
	 * Letter for a percentage.
	 *
	 * @param int $percent 0 to 100.
	 */
	public static function letter( int $percent ): string {
		foreach ( self::GRADES as $letter => $min ) {
			if ( $percent >= $min ) {
				return $letter;
			}
		}

		return 'F';
	}

	/**
	 * Lower-case names; repeated headers become a list.
	 *
	 * @param array<string,string|string[]> $headers Headers.
	 * @return array<string,string[]>
	 */
	public static function normalize( array $headers ): array {
		$out = array();
		foreach ( $headers as $name => $value ) {
			$name = strtolower( trim( (string) $name ) );
			foreach ( (array) $value as $item ) {
				if ( ! is_scalar( $item ) ) {
					continue;
				}
				// Several policies can be joined with commas; CSP sources never contain one.
				// Single-value headers contain a comma only when they were sent twice.
				$split = 0 === strpos( $name, 'content-security-policy' ) || in_array( $name, self::SINGLE_VALUE, true );
				$items = $split ? explode( ',', (string) $item ) : array( (string) $item );
				foreach ( $items as $part ) {
					if ( '' !== trim( $part ) ) {
						$out[ $name ][] = trim( $part );
					}
				}
			}
		}

		return $out;
	}

	/**
	 * First value of a header, or null.
	 *
	 * @param array<string,string[]> $h    Headers.
	 * @param string                 $name Lower-case name.
	 */
	private static function first( array $h, string $name ): ?string {
		return isset( $h[ $name ][0] ) ? $h[ $name ][0] : null;
	}

	/**
	 * Content-Security-Policy.
	 *
	 * @param array<string,string[]> $h Headers.
	 * @return array<string,mixed>
	 */
	private static function csp( array $h ): array {
		$max = 25;
		$fix = __( 'In Settings > Security Headers, pick a CSP preset, run it in Report-Only mode for a while, fix the violations, then switch to Enforce.', 'wp-security-headers' );

		$best = null;
		foreach ( $h['content-security-policy'] ?? array() as $value ) {
			$policy = Policy::parse( $value );
			if ( null !== $policy->effective( 'script-src' ) ) {
				$best = $policy;
				break;
			}
		}

		if ( null === $best ) {
			if ( isset( $h['content-security-policy-report-only'] ) ) {
				return self::finding( 'csp', 'Content-Security-Policy', self::WARN, 5, $max, __( 'Only a Report-Only policy is sent. It reports problems but blocks nothing.', 'wp-security-headers' ), __( 'Check the violations screen, adjust the policy and switch the mode to Enforce.', 'wp-security-headers' ) );
			}
			if ( isset( $h['content-security-policy'] ) ) {
				return self::finding( 'csp', 'Content-Security-Policy', self::FAIL, 0, $max, __( 'A policy is sent, but nothing in it restricts scripts (no default-src or script-src).', 'wp-security-headers' ), $fix );
			}

			return self::finding( 'csp', 'Content-Security-Policy', self::FAIL, 0, $max, __( 'No Content-Security-Policy. It is the main defence against cross-site scripting (XSS).', 'wp-security-headers' ), $fix );
		}

		$score    = $max;
		$problems = array();
		foreach ( $best->warnings() as $warning ) {
			if ( 'unsafe_inline' === $warning['code'] || 'broad_script' === $warning['code'] ) {
				$score -= 8;
			} elseif ( 'unsafe_eval' === $warning['code'] ) {
				$score -= 4;
			} elseif ( in_array( $warning['code'], array( 'object_src', 'base_uri' ), true ) ) {
				--$score;
			} else {
				continue;
			}
			$problems[] = $warning['message'];
		}
		$score = max( 5, $score );

		if ( array() === $problems ) {
			return self::finding( 'csp', 'Content-Security-Policy', self::PASS, $score, $max, __( 'An enforced policy restricts scripts.', 'wp-security-headers' ), '' );
		}

		return self::finding( 'csp', 'Content-Security-Policy', self::WARN, $score, $max, __( 'An enforced policy is sent, but it has weak spots.', 'wp-security-headers' ), implode( ' ', $problems ) );
	}

	/**
	 * Strict-Transport-Security.
	 *
	 * @param array<string,string[]> $h     Headers.
	 * @param bool                   $https HTTPS.
	 * @return array<string,mixed>
	 */
	private static function hsts( array $h, bool $https ): array {
		$max = 20;
		if ( ! $https ) {
			return self::finding( 'hsts', 'Strict-Transport-Security', self::FAIL, 0, $max, __( 'The site was scanned over plain HTTP. HSTS only works on HTTPS.', 'wp-security-headers' ), __( 'Install a certificate, change the site address to https:// in Settings > General, then turn on HSTS.', 'wp-security-headers' ) );
		}
		$value = self::first( $h, 'strict-transport-security' );
		$fix   = __( 'Turn on HSTS in Settings > Security Headers. Start with a short max-age, then raise it to 1 year or more.', 'wp-security-headers' );
		if ( null === $value ) {
			return self::finding( 'hsts', 'Strict-Transport-Security', self::FAIL, 0, $max, __( 'Missing. Browsers may still try plain HTTP first, which can be intercepted.', 'wp-security-headers' ), $fix );
		}
		$age = preg_match( '/max-age\s*=\s*"?(\d+)"?/i', $value, $m ) ? (int) $m[1] : 0;
		if ( $age <= 0 ) {
			return self::finding( 'hsts', 'Strict-Transport-Security', self::FAIL, 0, $max, __( 'max-age is 0 or missing, which switches HSTS off.', 'wp-security-headers' ), $fix );
		}
		if ( $age < Hsts::SIX_MONTHS ) {
			return self::finding( 'hsts', 'Strict-Transport-Security', self::WARN, 10, $max, __( 'max-age is shorter than 6 months.', 'wp-security-headers' ), __( 'Raise max-age to 31536000 (1 year) once every page works over HTTPS.', 'wp-security-headers' ) );
		}

		return self::finding( 'hsts', 'Strict-Transport-Security', self::PASS, $max, $max, __( 'Browsers will only use HTTPS for this site.', 'wp-security-headers' ), '' );
	}

	/**
	 * X-Frame-Options or frame-ancestors.
	 *
	 * @param array<string,string[]> $h Headers.
	 * @return array<string,mixed>
	 */
	private static function framing( array $h ): array {
		$max = 15;
		foreach ( $h['content-security-policy'] ?? array() as $value ) {
			if ( Policy::parse( $value )->has( 'frame-ancestors' ) ) {
				return self::finding( 'framing', 'frame-ancestors / X-Frame-Options', self::PASS, $max, $max, __( 'frame-ancestors controls who can embed the site.', 'wp-security-headers' ), '' );
			}
		}
		$values = array_values( array_unique( array_map( 'strtoupper', $h['x-frame-options'] ?? array() ) ) );
		$fix    = __( 'Set "Framing" to "Same origin only" or "Nobody" in Settings > Security Headers.', 'wp-security-headers' );
		if ( count( $values ) > 1 ) {
			return self::finding( 'framing', 'frame-ancestors / X-Frame-Options', self::FAIL, 0, $max, sprintf( /* translators: %s: header values. */ __( 'X-Frame-Options is sent with conflicting values (%s), so browsers ignore it.', 'wp-security-headers' ), implode( ', ', $values ) ), __( 'Send X-Frame-Options from one place only (this plugin, the web server or the CDN), or add frame-ancestors to the Content-Security-Policy.', 'wp-security-headers' ) );
		}
		$xfo = $values[0] ?? '';
		if ( in_array( $xfo, array( 'DENY', 'SAMEORIGIN' ), true ) ) {
			return self::finding( 'framing', 'frame-ancestors / X-Frame-Options', self::PASS, $max, $max, __( 'X-Frame-Options blocks embedding by other sites.', 'wp-security-headers' ), '' );
		}
		if ( '' !== $xfo ) {
			return self::finding( 'framing', 'frame-ancestors / X-Frame-Options', self::FAIL, 0, $max, __( 'X-Frame-Options has a value browsers no longer support (such as ALLOW-FROM).', 'wp-security-headers' ), $fix );
		}

		return self::finding( 'framing', 'frame-ancestors / X-Frame-Options', self::FAIL, 0, $max, __( 'Any site can embed yours in a frame (clickjacking).', 'wp-security-headers' ), $fix );
	}

	/**
	 * X-Content-Type-Options.
	 *
	 * @param array<string,string[]> $h Headers.
	 * @return array<string,mixed>
	 */
	private static function nosniff( array $h ): array {
		if ( 'nosniff' === strtolower( (string) self::first( $h, 'x-content-type-options' ) ) ) {
			return self::finding( 'nosniff', 'X-Content-Type-Options', self::PASS, 10, 10, __( 'Browsers will not guess content types.', 'wp-security-headers' ), '' );
		}

		return self::finding( 'nosniff', 'X-Content-Type-Options', self::FAIL, 0, 10, __( 'Missing. Browsers may treat uploaded files as scripts or styles.', 'wp-security-headers' ), __( 'Turn on X-Content-Type-Options: nosniff in Settings > Security Headers.', 'wp-security-headers' ) );
	}

	/**
	 * Referrer-Policy.
	 *
	 * @param array<string,string[]> $h Headers.
	 * @return array<string,mixed>
	 */
	private static function referrer( array $h ): array {
		$max   = 10;
		$fix   = __( 'Set Referrer-Policy to strict-origin-when-cross-origin in Settings > Security Headers.', 'wp-security-headers' );
		$value = self::first( $h, 'referrer-policy' );
		if ( null === $value ) {
			return self::finding( 'referrer', 'Referrer-Policy', self::WARN, 5, $max, __( 'Missing. Modern browsers default to strict-origin-when-cross-origin, older ones send full URLs to other sites.', 'wp-security-headers' ), $fix );
		}
		// Browsers use the last value they understand.
		$policy = '';
		foreach ( array_map( 'trim', explode( ',', strtolower( $value ) ) ) as $item ) {
			if ( in_array( $item, Sanitizer::REFERRER_POLICIES, true ) ) {
				$policy = $item;
			}
		}
		if ( in_array( $policy, array( 'no-referrer', 'same-origin', 'strict-origin', 'strict-origin-when-cross-origin' ), true ) ) {
			return self::finding( 'referrer', 'Referrer-Policy', self::PASS, $max, $max, __( 'Full URLs are not sent to other sites.', 'wp-security-headers' ), '' );
		}
		if ( in_array( $policy, array( 'origin', 'origin-when-cross-origin' ), true ) ) {
			return self::finding( 'referrer', 'Referrer-Policy', self::WARN, 7, $max, __( 'The origin is sent even from HTTPS to HTTP pages.', 'wp-security-headers' ), $fix );
		}

		return self::finding( 'referrer', 'Referrer-Policy', self::FAIL, 0, $max, __( 'Full URLs, including query strings, can leak to other sites.', 'wp-security-headers' ), $fix );
	}

	/**
	 * Permissions-Policy.
	 *
	 * @param array<string,string[]> $h Headers.
	 * @return array<string,mixed>
	 */
	private static function permissions( array $h ): array {
		$fix = __( 'Open the Permissions-Policy builder in Settings > Security Headers and switch off the features your site does not use.', 'wp-security-headers' );
		if ( '' !== (string) self::first( $h, 'permissions-policy' ) ) {
			return self::finding( 'permissions', 'Permissions-Policy', self::PASS, 10, 10, __( 'Browser features such as camera and location are restricted.', 'wp-security-headers' ), '' );
		}
		if ( null !== self::first( $h, 'feature-policy' ) ) {
			return self::finding( 'permissions', 'Permissions-Policy', self::WARN, 5, 10, __( 'Only the old Feature-Policy header is sent.', 'wp-security-headers' ), $fix );
		}

		return self::finding( 'permissions', 'Permissions-Policy', self::FAIL, 0, 10, __( 'Missing. Embedded content may ask for camera, microphone or location.', 'wp-security-headers' ), $fix );
	}

	/**
	 * Cross-Origin-Opener-Policy.
	 *
	 * @param array<string,string[]> $h Headers.
	 * @return array<string,mixed>
	 */
	private static function coop( array $h ): array {
		$value = strtolower( (string) self::first( $h, 'cross-origin-opener-policy' ) );
		if ( in_array( $value, array( 'same-origin', 'same-origin-allow-popups' ), true ) ) {
			return self::finding( 'coop', 'Cross-Origin-Opener-Policy', self::PASS, 5, 5, __( 'Other sites opened in a popup cannot reach this window.', 'wp-security-headers' ), '' );
		}

		return self::finding( 'coop', 'Cross-Origin-Opener-Policy', self::WARN, 0, 5, __( 'Not set. Pages from other origins keep a reference to this window.', 'wp-security-headers' ), __( 'Set Cross-Origin-Opener-Policy to same-origin-allow-popups (safe with most payment and login popups).', 'wp-security-headers' ) );
	}

	/**
	 * Cross-Origin-Resource-Policy.
	 *
	 * @param array<string,string[]> $h Headers.
	 * @return array<string,mixed>
	 */
	private static function corp( array $h ): array {
		$value = strtolower( (string) self::first( $h, 'cross-origin-resource-policy' ) );
		if ( in_array( $value, array( 'same-origin', 'same-site' ), true ) ) {
			return self::finding( 'corp', 'Cross-Origin-Resource-Policy', self::PASS, 5, 5, __( 'Other sites cannot load this response as a resource.', 'wp-security-headers' ), '' );
		}
		if ( 'cross-origin' === $value ) {
			return self::finding( 'corp', 'Cross-Origin-Resource-Policy', self::PASS, 3, 5, __( 'Set to cross-origin, which allows every site.', 'wp-security-headers' ), '' );
		}

		return self::finding( 'corp', 'Cross-Origin-Resource-Policy', self::WARN, 0, 5, __( 'Not set.', 'wp-security-headers' ), __( 'Set Cross-Origin-Resource-Policy to same-site for pages. Images and fonts loaded by other sites are served by the web server, not by this header.', 'wp-security-headers' ) );
	}

	/**
	 * Headers that reveal software versions. Informational only.
	 *
	 * @param array<string,string[]> $h Headers.
	 * @return array<int,array<string,mixed>>
	 */
	private static function leaks( array $h ): array {
		$out     = array();
		$powered = self::first( $h, 'x-powered-by' );
		if ( null !== $powered ) {
			$out[] = self::finding( 'x_powered_by', 'X-Powered-By', self::INFO, 0, 0, sprintf( /* translators: %s: header value. */ __( 'Reveals "%s".', 'wp-security-headers' ), $powered ), __( 'Turn on "Remove X-Powered-By", or set expose_php = Off in php.ini.', 'wp-security-headers' ) );
		}
		$server = self::first( $h, 'server' );
		if ( null !== $server && preg_match( '/\d/', $server ) ) {
			$out[] = self::finding( 'server', 'Server', self::INFO, 0, 0, sprintf( /* translators: %s: header value. */ __( 'Reveals the server version "%s".', 'wp-security-headers' ), $server ), __( 'Hide the version in the web server (server_tokens off in nginx, ServerTokens Prod in Apache).', 'wp-security-headers' ) );
		}
		$xss = self::first( $h, 'x-xss-protection' );
		if ( null !== $xss && '0' !== trim( $xss ) ) {
			$out[] = self::finding( 'x_xss_protection', 'X-XSS-Protection', self::INFO, 0, 0, __( 'This header is obsolete and its filter could be abused in old browsers.', 'wp-security-headers' ), __( 'Remove it or set it to 0, and rely on Content-Security-Policy.', 'wp-security-headers' ) );
		}

		return $out;
	}

	/**
	 * Single-value headers that were sent more than once. Informational only.
	 *
	 * @param array<string,string[]> $h Headers.
	 * @return array<int,array<string,mixed>>
	 */
	private static function duplicates( array $h ): array {
		$out = array();
		foreach ( self::SINGLE_VALUE as $name ) {
			$values = $h[ $name ] ?? array();
			if ( count( $values ) < 2 ) {
				continue;
			}
			$label    = implode( '-', array_map( 'ucfirst', explode( '-', $name ) ) );
			$distinct = array_values( array_unique( array_map( 'strtolower', $values ) ) );
			if ( 1 === count( $distinct ) ) {
				/* translators: 1: header name, 2: number of times. */
				$message = sprintf( __( '%1$s is sent %2$d times with the same value.', 'wp-security-headers' ), $label, count( $values ) );
			} else {
				/* translators: 1: header name, 2: number of times, 3: the values. */
				$message = sprintf( __( '%1$s is sent %2$d times with different values (%3$s); browsers use the first one or ignore the header.', 'wp-security-headers' ), $label, count( $values ), implode( ' | ', $values ) );
			}
			$out[] = self::finding( 'duplicate_' . str_replace( '-', '_', $name ), $label, self::INFO, 0, 0, $message, __( 'The header is set in two places, usually this plugin and the web server or CDN. Switch it off in one of them.', 'wp-security-headers' ) );
		}

		return $out;
	}

	/**
	 * One finding.
	 *
	 * @param string $key     Key.
	 * @param string $header  Header label.
	 * @param string $status  pass, warn, fail or info.
	 * @param int    $score   Points earned.
	 * @param int    $max     Points available.
	 * @param string $message What was found.
	 * @param string $fix     How to fix it ('' when nothing to do).
	 * @return array<string,mixed>
	 */
	private static function finding( string $key, string $header, string $status, int $score, int $max, string $message, string $fix ): array {
		return array(
			'key'     => $key,
			'header'  => $header,
			'status'  => $status,
			'score'   => $score,
			'max'     => $max,
			'message' => $message,
			'fix'     => $fix,
		);
	}
}
