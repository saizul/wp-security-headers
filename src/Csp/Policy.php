<?php
/**
 * Content-Security-Policy model: sanitising, parsing and serialising.
 *
 * @package Saizul\SecurityHeaders
 */

namespace Saizul\SecurityHeaders\Csp;

defined( 'ABSPATH' ) || exit;

/**
 * An immutable set of CSP directives.
 *
 * Directive names are lower case. Values are lists of source expressions
 * (or tokens for directives such as `sandbox` and `report-to`).
 */
final class Policy {

	/**
	 * Known directives, in the order they are serialised.
	 */
	const DIRECTIVES = array(
		'default-src',
		'script-src',
		'script-src-elem',
		'script-src-attr',
		'style-src',
		'style-src-elem',
		'style-src-attr',
		'img-src',
		'font-src',
		'connect-src',
		'media-src',
		'object-src',
		'frame-src',
		'child-src',
		'worker-src',
		'manifest-src',
		'base-uri',
		'form-action',
		'frame-ancestors',
		'sandbox',
		'require-trusted-types-for',
		'trusted-types',
		'upgrade-insecure-requests',
		'report-uri',
		'report-to',
	);

	/**
	 * Directives that take no value.
	 */
	const VALUELESS = array( 'upgrade-insecure-requests' );

	/**
	 * Fetch directives that fall back to default-src.
	 */
	const FETCH = array(
		'script-src',
		'script-src-elem',
		'script-src-attr',
		'style-src',
		'style-src-elem',
		'style-src-attr',
		'img-src',
		'font-src',
		'connect-src',
		'media-src',
		'object-src',
		'frame-src',
		'child-src',
		'worker-src',
		'manifest-src',
	);

	/**
	 * Keyword sources (without quotes).
	 */
	const KEYWORDS = array(
		'self',
		'none',
		'unsafe-inline',
		'unsafe-eval',
		'strict-dynamic',
		'unsafe-hashes',
		'report-sample',
		'wasm-unsafe-eval',
		'inline-speculation-rules',
	);

	/**
	 * Most sources kept per directive.
	 */
	const MAX_SOURCES = 64;

	/**
	 * Directives.
	 *
	 * @var array<string,string[]>
	 */
	private $directives;

	/**
	 * Constructor. Use from_array() or parse().
	 *
	 * @param array<string,string[]> $directives Directives, already clean.
	 */
	private function __construct( array $directives ) {
		$this->directives = $directives;
	}

	/**
	 * Build a sanitised policy from a directive => sources map.
	 *
	 * Sources may be a space separated string or a list. Unknown directives
	 * and invalid sources are dropped, bare keywords such as `self` are quoted.
	 *
	 * @param array<mixed,mixed> $map Directive => sources.
	 */
	public static function from_array( array $map ): self {
		$directives = array();
		foreach ( $map as $name => $sources ) {
			$name = strtolower( trim( (string) $name ) );
			if ( ! in_array( $name, self::DIRECTIVES, true ) ) {
				continue;
			}
			if ( in_array( $name, self::VALUELESS, true ) ) {
				if ( false !== $sources && null !== $sources ) {
					$directives[ $name ] = array();
				}
				continue;
			}
			$clean = self::sanitize_sources( $name, $sources );
			if ( array() !== $clean || 'sandbox' === $name ) {
				$directives[ $name ] = $clean;
			}
		}

		return new self( $directives );
	}

	/**
	 * Parse a header value as browsers do. Values are not sanitised, so this
	 * can describe any policy found on a site. The first occurrence of a
	 * directive wins.
	 *
	 * @param string $header Header value.
	 */
	public static function parse( string $header ): self {
		$directives = array();
		foreach ( explode( ';', $header ) as $part ) {
			$tokens = preg_split( '/[\s]+/', trim( $part ), -1, PREG_SPLIT_NO_EMPTY );
			if ( ! is_array( $tokens ) || array() === $tokens ) {
				continue;
			}
			$name = strtolower( (string) array_shift( $tokens ) );
			if ( ! isset( $directives[ $name ] ) ) {
				$directives[ $name ] = array_values( $tokens );
			}
		}

		return new self( $directives );
	}

	/**
	 * Sanitise the sources of one directive.
	 *
	 * @param string $directive Directive name.
	 * @param mixed  $sources   Space separated string or list.
	 * @return string[]
	 */
	public static function sanitize_sources( string $directive, $sources ): array {
		if ( is_string( $sources ) ) {
			$sources = preg_split( '/[\s]+/', $sources, -1, PREG_SPLIT_NO_EMPTY );
		}
		if ( ! is_array( $sources ) ) {
			return array();
		}

		$clean = array();
		foreach ( $sources as $source ) {
			if ( ! is_string( $source ) ) {
				continue;
			}
			$token = self::sanitize_token( $directive, $source );
			if ( null !== $token && ! in_array( $token, $clean, true ) ) {
				$clean[] = $token;
			}
			if ( count( $clean ) >= self::MAX_SOURCES ) {
				break;
			}
		}

		// 'none' is ignored by browsers when other sources are present.
		if ( count( $clean ) > 1 ) {
			$clean = array_values( array_diff( $clean, array( "'none'" ) ) );
		}

		return $clean;
	}

	/**
	 * Sanitise one token for a directive.
	 *
	 * @param string $directive Directive name.
	 * @param string $token     Raw token.
	 */
	public static function sanitize_token( string $directive, string $token ): ?string {
		$token = trim( $token );
		if ( '' === $token || strlen( $token ) > 512 || preg_match( '/[\x00-\x20\x7f;,]/', $token ) ) {
			return null;
		}

		switch ( $directive ) {
			case 'report-uri':
				return preg_match( '#^(https?://[^\s\'"<>]+|/[^\s\'"<>]*)$#i', $token ) ? $token : null;

			case 'report-to':
				return preg_match( '/^[A-Za-z0-9_-]{1,64}$/', $token ) ? $token : null;

			case 'sandbox':
				$token = strtolower( $token );
				return preg_match( '/^allow-[a-z-]{2,40}$/', $token ) ? $token : null;

			case 'require-trusted-types-for':
				return in_array( strtolower( trim( $token, "'" ) ), array( 'script' ), true ) ? "'script'" : null;

			case 'trusted-types':
				if ( in_array( strtolower( trim( $token, "'" ) ), array( 'none', 'allow-duplicates' ), true ) ) {
					return "'" . strtolower( trim( $token, "'" ) ) . "'";
				}
				return preg_match( '/^(\*|[A-Za-z0-9\-#=_\/@.%]{1,64})$/', $token ) ? $token : null;
		}

		return self::sanitize_source( $token );
	}

	/**
	 * Sanitise a source expression (host, scheme, keyword or hash).
	 *
	 * Nonces are refused: the plugin adds a fresh nonce on every request.
	 *
	 * @param string $source Raw source.
	 */
	public static function sanitize_source( string $source ): ?string {
		$source = trim( $source );
		if ( '' === $source || preg_match( '/[\x00-\x20\x7f;,"<>\\\\]/', $source ) ) {
			return null;
		}

		$bare = strtolower( trim( $source, "'" ) );
		if ( in_array( $bare, self::KEYWORDS, true ) ) {
			return "'" . $bare . "'";
		}
		if ( preg_match( "/^'(sha256|sha384|sha512)-([A-Za-z0-9+\/_-]+={0,2})'$/i", $source, $m ) ) {
			return "'" . strtolower( $m[1] ) . '-' . $m[2] . "'";
		}
		if ( false !== strpos( $source, "'" ) ) {
			return null;
		}
		if ( '*' === $source ) {
			return '*';
		}
		if ( preg_match( '/^[a-z][a-z0-9+.-]*:$/i', $source ) ) {
			return strtolower( $source );
		}
		if ( preg_match( '#^(?:([a-z][a-z0-9+.-]*)://)?(\*|(?:\*\.)?[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*)(:(?:[0-9]{1,5}|\*))?(/[^\s]*)?$#i', $source, $m ) ) {
			$scheme = isset( $m[1] ) && '' !== $m[1] ? strtolower( $m[1] ) . '://' : '';
			$port   = $m[3] ?? '';
			$path   = $m[4] ?? '';

			return $scheme . strtolower( $m[2] ) . $port . $path;
		}

		return null;
	}

	/**
	 * Whether the policy has a directive.
	 *
	 * @param string $name Directive.
	 */
	public function has( string $name ): bool {
		return array_key_exists( $name, $this->directives );
	}

	/**
	 * Sources of a directive, or null when it is not set.
	 *
	 * @param string $name Directive.
	 * @return string[]|null
	 */
	public function get( string $name ): ?array {
		return $this->directives[ $name ] ?? null;
	}

	/**
	 * Sources that apply to a fetch directive, following the fallback chain
	 * (script-src-elem -> script-src -> default-src).
	 *
	 * @param string $name Directive.
	 * @return string[]|null Null when nothing restricts it.
	 */
	public function effective( string $name ): ?array {
		$chain = array( $name );
		if ( preg_match( '/^(script|style)-src-(elem|attr)$/', $name, $m ) ) {
			$chain[] = $m[1] . '-src';
		}
		if ( in_array( $name, array( 'frame-src', 'worker-src' ), true ) ) {
			$chain[] = 'child-src';
		}
		if ( 'worker-src' === $name ) {
			$chain[] = 'script-src';
		}
		if ( in_array( $name, self::FETCH, true ) ) {
			$chain[] = 'default-src';
		}
		foreach ( $chain as $directive ) {
			if ( isset( $this->directives[ $directive ] ) ) {
				return $this->directives[ $directive ];
			}
		}

		return null;
	}

	/**
	 * A copy with a directive replaced.
	 *
	 * @param string   $name    Directive.
	 * @param string[] $sources Sources (trusted).
	 */
	public function with( string $name, array $sources ): self {
		$copy                      = clone $this;
		$copy->directives[ $name ] = array_values( array_unique( $sources ) );

		return $copy;
	}

	/**
	 * A copy with sources appended to a directive. When the directive is not
	 * set, it starts from what it currently inherits from default-src so the
	 * policy does not become weaker.
	 *
	 * @param string   $name    Directive.
	 * @param string[] $sources Sources (trusted).
	 */
	public function add( string $name, array $sources ): self {
		$current = $this->has( $name ) ? (array) $this->get( $name ) : (array) $this->effective( $name );
		$current = array_values( array_diff( $current, array( "'none'" ) ) );

		return $this->with( $name, array_merge( $current, $sources ) );
	}

	/**
	 * A copy without a directive.
	 *
	 * @param string $name Directive.
	 */
	public function without( string $name ): self {
		$copy = clone $this;
		unset( $copy->directives[ $name ] );

		return $copy;
	}

	/**
	 * Directive => sources.
	 *
	 * @return array<string,string[]>
	 */
	public function to_array(): array {
		return $this->directives;
	}

	/**
	 * Whether the policy has no directives.
	 */
	public function is_empty(): bool {
		return array() === $this->directives;
	}

	/**
	 * Header value, directives in a stable order.
	 */
	public function serialize(): string {
		$names = array_keys( $this->directives );
		usort(
			$names,
			static function ( $a, $b ) {
				$pa = array_search( $a, self::DIRECTIVES, true );
				$pb = array_search( $b, self::DIRECTIVES, true );
				$pa = false === $pa ? 999 : $pa;
				$pb = false === $pb ? 999 : $pb;

				return $pa === $pb ? strcmp( $a, $b ) : $pa - $pb;
			}
		);

		$parts = array();
		foreach ( $names as $name ) {
			$sources = $this->directives[ $name ];
			if ( array() === $sources && ! in_array( $name, self::VALUELESS, true ) && 'sandbox' !== $name ) {
				continue;
			}
			$parts[] = trim( $name . ' ' . implode( ' ', $sources ) );
		}

		return implode( '; ', $parts );
	}

	/**
	 * Whether a source list allows scripts by nonce, hash or strict-dynamic,
	 * which makes browsers ignore 'unsafe-inline'.
	 *
	 * @param string[] $sources Sources.
	 */
	public static function neutralises_unsafe_inline( array $sources ): bool {
		foreach ( $sources as $source ) {
			if ( preg_match( "/^'(nonce-|sha256-|sha384-|sha512-|strict-dynamic')/i", $source ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Weak spots of the policy, worst first.
	 *
	 * @return array<int,array{code:string,severity:string,message:string}>
	 */
	public function warnings(): array {
		$out    = array();
		$script = $this->effective( 'script-src' );
		$lower  = static function ( array $items ): array {
			return array_map( 'strtolower', $items );
		};

		if ( null === $script ) {
			$out[] = self::warning( 'no_script_src', 'high', __( 'Nothing restricts scripts: add default-src or script-src.', 'wp-security-headers' ) );
		} else {
			$sources = $lower( $script );
			$guarded = self::neutralises_unsafe_inline( $sources );
			if ( in_array( "'unsafe-inline'", $sources, true ) && ! $guarded ) {
				$out[] = self::warning( 'unsafe_inline', 'high', __( "script-src allows 'unsafe-inline', so injected inline scripts run. Turn on nonces and remove 'unsafe-inline' when your theme and plugins allow it.", 'wp-security-headers' ) );
			}
			if ( in_array( "'unsafe-inline'", $sources, true ) && $guarded ) {
				$out[] = self::warning( 'unsafe_inline_ignored', 'info', __( "Browsers ignore 'unsafe-inline' when a nonce, hash or 'strict-dynamic' is present. It only helps very old browsers, and inline scripts without the nonce are blocked.", 'wp-security-headers' ) );
			}
			if ( in_array( "'unsafe-eval'", $sources, true ) ) {
				$out[] = self::warning( 'unsafe_eval', 'medium', __( "script-src allows 'unsafe-eval' (eval() and new Function()). Remove it unless a script you trust needs it.", 'wp-security-headers' ) );
			}
			$broad = array_intersect( $sources, array( '*', 'https:', 'http:', 'data:', 'blob:' ) );
			if ( array() !== $broad && ! in_array( "'strict-dynamic'", $sources, true ) ) {
				$out[] = self::warning(
					'broad_script',
					'high',
					sprintf(
						/* translators: %s: source expressions such as https: or *. */
						__( 'script-src allows %s, which lets scripts load from almost anywhere. List the hosts you need instead.', 'wp-security-headers' ),
						implode( ' ', $broad )
					)
				);
			}
		}

		$object = $this->effective( 'object-src' );
		if ( null === $object || array( "'none'" ) !== $lower( $object ) ) {
			$out[] = self::warning( 'object_src', 'medium', __( "Set object-src 'none' to block plugins such as Flash and <object> embeds.", 'wp-security-headers' ) );
		}
		if ( ! $this->has( 'base-uri' ) ) {
			$out[] = self::warning( 'base_uri', 'medium', __( "Set base-uri 'self' (or 'none') so injected <base> tags cannot redirect relative script URLs.", 'wp-security-headers' ) );
		}
		if ( ! $this->has( 'default-src' ) ) {
			$out[] = self::warning( 'default_src', 'low', __( 'Add default-src as a fallback for the directives you did not set.', 'wp-security-headers' ) );
		}
		foreach ( $this->directives as $name => $sources ) {
			foreach ( $sources as $source ) {
				if ( 0 === stripos( $source, 'http://' ) || 'http:' === strtolower( $source ) ) {
					$out[] = self::warning(
						'insecure_source',
						'low',
						sprintf(
							/* translators: %s: directive name. */
							__( '%s allows plain http sources. Use https.', 'wp-security-headers' ),
							$name
						)
					);
					break 2;
				}
			}
		}

		$rank = array(
			'high'   => 0,
			'medium' => 1,
			'low'    => 2,
			'info'   => 3,
		);
		// Stable sort by severity (usort is not stable before PHP 8).
		$keys = array_keys( $out );
		usort(
			$keys,
			static function ( $a, $b ) use ( $rank, $out ) {
				$diff = $rank[ $out[ $a ]['severity'] ] - $rank[ $out[ $b ]['severity'] ];

				return 0 === $diff ? $a - $b : $diff;
			}
		);

		return array_map(
			static function ( $key ) use ( $out ) {
				return $out[ $key ];
			},
			$keys
		);
	}

	/**
	 * One warning.
	 *
	 * @param string $code     Code.
	 * @param string $severity Severity.
	 * @param string $message  Message.
	 * @return array{code:string,severity:string,message:string}
	 */
	private static function warning( string $code, string $severity, string $message ): array {
		return array(
			'code'     => $code,
			'severity' => $severity,
			'message'  => $message,
		);
	}
}
