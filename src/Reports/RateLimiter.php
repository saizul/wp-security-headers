<?php
/**
 * Fixed-window rate limiter on transients.
 *
 * @package Saizul\SecurityHeaders
 */

namespace Saizul\SecurityHeaders\Reports;

defined( 'ABSPATH' ) || exit;

/**
 * Counts hits per key in a fixed window. Uses transients, so it works with
 * or without a persistent object cache. Not strictly atomic, which is fine
 * for keeping report floods out of the database.
 */
final class RateLimiter {

	const PREFIX = 'wpsh_rl_';

	/**
	 * Hits allowed per window.
	 *
	 * @var int
	 */
	private $limit;

	/**
	 * Window length in seconds.
	 *
	 * @var int
	 */
	private $window;

	/**
	 * Constructor.
	 *
	 * @param int $limit  Hits allowed per window.
	 * @param int $window Window in seconds.
	 */
	public function __construct( int $limit, int $window = 60 ) {
		$this->limit  = max( 1, $limit );
		$this->window = max( 1, $window );
	}

	/**
	 * Count a hit and tell whether it is allowed.
	 *
	 * @param string $key Bucket key (already hashed or a fixed name).
	 * @param int    $now Current time.
	 */
	public function hit( string $key, int $now ): bool {
		$name  = self::PREFIX . substr( md5( $key ), 0, 24 );
		$state = get_transient( $name );
		if ( ! is_array( $state ) || ! isset( $state['start'], $state['count'] ) || $now - (int) $state['start'] >= $this->window ) {
			$state = array(
				'start' => $now,
				'count' => 0,
			);
		}
		if ( (int) $state['count'] >= $this->limit ) {
			return false;
		}
		++$state['count'];
		set_transient( $name, $state, $this->window );

		return true;
	}

	/**
	 * Seconds until the window of a key resets.
	 *
	 * @param string $key Bucket key.
	 * @param int    $now Current time.
	 */
	public function retry_after( string $key, int $now ): int {
		$state = get_transient( self::PREFIX . substr( md5( $key ), 0, 24 ) );
		if ( ! is_array( $state ) || ! isset( $state['start'] ) ) {
			return 0;
		}

		return max( 0, $this->window - ( $now - (int) $state['start'] ) );
	}
}
