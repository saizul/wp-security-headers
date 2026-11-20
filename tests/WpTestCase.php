<?php
declare(strict_types=1);

namespace Saizul\SecurityHeaders\Tests;

use PHPUnit\Framework\TestCase;
use Saizul\SecurityHeaders\Nonce;
use Saizul\SecurityHeaders\Plugin;
use Saizul\SecurityHeaders\Settings;
use WP_CLI;
use WpStubs;

/**
 * Base class: resets the WordPress and WP-CLI stubs before every test.
 */
abstract class WpTestCase extends TestCase {

	protected function setUp(): void {
		WpStubs::reset();
		WP_CLI::reset();
		Plugin::reset();
		Nonce::reset();
		$_GET     = array();
		$_POST    = array();
		$_REQUEST = array();
	}

	/**
	 * Default settings merged with overrides.
	 *
	 * @param array<string,mixed> $overrides Overrides.
	 * @return array<string,mixed>
	 */
	protected static function settings( array $overrides = array() ): array {
		return array_merge( Settings::defaults(), $overrides );
	}

	/**
	 * Store settings in the option stub.
	 *
	 * @param array<string,mixed> $overrides Overrides.
	 */
	protected static function store( array $overrides = array() ): void {
		WpStubs::$options[ Settings::OPTION ] = self::settings( $overrides );
	}

	/**
	 * Headers as name => value (last wins), for assertions.
	 *
	 * @param array<int,array{0:string,1:string}> $headers Headers.
	 * @return array<string,string>
	 */
	protected static function map( array $headers ): array {
		$out = array();
		foreach ( $headers as $header ) {
			$out[ $header[0] ] = $header[1];
		}
		return $out;
	}
}
