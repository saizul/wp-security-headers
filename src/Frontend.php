<?php
/**
 * Sends the headers.
 *
 * @package Saizul\SecurityHeaders
 */

namespace Saizul\SecurityHeaders;

defined( 'ABSPATH' ) || exit;

/**
 * Hooks `send_headers` for the front end and, when switched on,
 * `admin_init` and `login_init`. Adds the CSP nonce to script tags.
 */
final class Frontend {

	/**
	 * Plugin.
	 *
	 * @var Plugin
	 */
	private $plugin;

	/**
	 * Sends one header line. `header()` by default.
	 *
	 * @var callable
	 */
	private $emit;

	/**
	 * Removes a header. `header_remove()` by default.
	 *
	 * @var callable
	 */
	private $remove;

	/**
	 * Tells whether headers were already sent. `headers_sent()` by default.
	 *
	 * @var callable
	 */
	private $sent;

	/**
	 * Constructor.
	 *
	 * @param Plugin        $plugin Plugin.
	 * @param callable|null $emit   Header sender (tests).
	 * @param callable|null $remove Header remover (tests).
	 * @param callable|null $sent   Headers-sent check (tests).
	 */
	public function __construct( Plugin $plugin, ?callable $emit = null, ?callable $remove = null, ?callable $sent = null ) {
		$this->plugin = $plugin;
		$this->emit   = $emit ?? static function ( string $line ): void {
			header( $line, true );
		};
		$this->remove = $remove ?? static function ( string $name ): void {
			header_remove( $name );
		};
		$this->sent   = $sent ?? 'headers_sent';
	}

	/**
	 * Register hooks.
	 */
	public function register(): void {
		$settings = $this->plugin->settings();

		add_action( 'send_headers', array( $this, 'send_front' ) );
		if ( ! empty( $settings['apply_admin'] ) ) {
			add_action( 'admin_init', array( $this, 'send_admin' ), 1 );
		}
		if ( ! empty( $settings['apply_login'] ) ) {
			add_action( 'login_init', array( $this, 'send_login' ), 1 );
		}
		if ( Settings::CSP_OFF !== $settings['csp_mode'] && ! empty( $settings['csp_nonce'] ) ) {
			add_filter( 'wp_script_attributes', array( Nonce::class, 'add_attribute' ) );
			add_filter( 'wp_inline_script_attributes', array( Nonce::class, 'add_attribute' ) );
		}
	}

	/**
	 * Front-end headers.
	 */
	public function send_front(): void {
		$this->send( HeaderBuilder::AREA_FRONT );
	}

	/**
	 * Headers for wp-admin (without the CSP).
	 */
	public function send_admin(): void {
		$this->send( HeaderBuilder::AREA_ADMIN );
	}

	/**
	 * Headers for wp-login.php (without the CSP).
	 */
	public function send_login(): void {
		$this->send( HeaderBuilder::AREA_LOGIN );
	}

	/**
	 * Send the headers of an area.
	 *
	 * @param string $area Area.
	 * @return int Number of headers sent.
	 */
	public function send( string $area ): int {
		if ( call_user_func( $this->sent ) ) {
			return 0;
		}
		$settings = $this->plugin->settings();
		if ( ! empty( $settings['remove_powered_by'] ) ) {
			call_user_func( $this->remove, 'X-Powered-By' );
		}

		$count = 0;
		foreach ( $this->plugin->headers( $area ) as $header ) {
			call_user_func( $this->emit, $header[0] . ': ' . $header[1] );
			++$count;
		}

		return $count;
	}
}
