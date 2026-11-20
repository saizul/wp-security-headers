<?php
/**
 * Plugin bootstrap.
 *
 * @package Saizul\SecurityHeaders
 */

namespace Saizul\SecurityHeaders;

use Saizul\SecurityHeaders\Admin\SettingsPage;
use Saizul\SecurityHeaders\Admin\Tools;
use Saizul\SecurityHeaders\Cli\Command;
use Saizul\SecurityHeaders\Reports\Endpoint;
use Saizul\SecurityHeaders\Reports\Store;

defined( 'ABSPATH' ) || exit;

/**
 * Wires headers, the report endpoint, the admin screens and WP-CLI.
 */
final class Plugin {

	const VERSION = '0.1.0';

	/**
	 * Running instance.
	 *
	 * @var Plugin|null
	 */
	private static $instance;

	/**
	 * Main plugin file.
	 *
	 * @var string
	 */
	private $file;

	/**
	 * Report store.
	 *
	 * @var Store|null
	 */
	private $store;

	/**
	 * Constructor.
	 *
	 * @param string $file Main plugin file.
	 */
	public function __construct( string $file ) {
		$this->file = $file;
	}

	/**
	 * Create the instance and register the hooks.
	 *
	 * @param string $file Main plugin file.
	 */
	public static function boot( string $file ): self {
		if ( null === self::$instance ) {
			self::$instance = new self( $file );
			self::$instance->hooks();
		}

		return self::$instance;
	}

	/**
	 * Running instance, if booted.
	 */
	public static function instance(): ?self {
		return self::$instance;
	}

	/**
	 * Forget the instance (tests).
	 */
	public static function reset(): void {
		self::$instance = null;
	}

	/**
	 * Register hooks.
	 */
	public function hooks(): void {
		add_action( 'init', array( $this, 'init' ) );

		( new Frontend( $this ) )->register();
		( new Endpoint( $this->store() ) )->register();

		if ( is_admin() ) {
			( new SettingsPage( $this ) )->register();
			( new Tools( $this ) )->register();
		}
		if ( defined( 'WP_CLI' ) && WP_CLI && class_exists( '\WP_CLI' ) ) {
			\WP_CLI::add_command( 'security-headers', new Command( $this ) );
		}
	}

	/**
	 * Load translations and make sure the report table exists while
	 * reporting is on (cheap: one autoloaded option).
	 */
	public function init(): void {
		load_plugin_textdomain( 'wp-security-headers', false, dirname( plugin_basename( $this->file ) ) . '/languages' );

		$settings = $this->settings();
		if ( ! empty( $settings['csp_report'] ) && Settings::CSP_OFF !== $settings['csp_mode'] ) {
			$this->store()->maybe_install();
		}
	}

	/**
	 * Activation: create the report table.
	 */
	public static function activate(): void {
		( new Store() )->install();
	}

	/**
	 * Current settings.
	 *
	 * @return array<string,mixed>
	 */
	public function settings(): array {
		return Settings::get();
	}

	/**
	 * Report store.
	 */
	public function store(): Store {
		if ( null === $this->store ) {
			$this->store = new Store();
		}

		return $this->store;
	}

	/**
	 * Headers for the current request.
	 *
	 * @param string    $area  front, admin or login.
	 * @param bool|null $https Override HTTPS detection.
	 * @return array<int,array{0:string,1:string}>
	 */
	public function headers( string $area, ?bool $https = null ): array {
		$settings = $this->settings();
		$headers  = HeaderBuilder::build(
			$settings,
			array(
				'area'       => $area,
				'https'      => null === $https ? is_ssl() : $https,
				'nonce'      => ! empty( $settings['csp_nonce'] ) ? Nonce::value() : null,
				'report_url' => Endpoint::url(),
			)
		);

		/**
		 * Filters the headers before they are sent.
		 *
		 * @param array<int,array{0:string,1:string}> $headers  Name, value pairs.
		 * @param string                              $area     front, admin or login.
		 * @param array<string,mixed>                 $settings Settings.
		 */
		$headers = apply_filters( 'security_headers_headers', $headers, $area, $settings );

		return is_array( $headers ) ? self::clean( $headers ) : array();
	}

	/**
	 * Drop malformed entries a filter may have added (header injection).
	 *
	 * @param array<mixed> $headers Headers.
	 * @return array<int,array{0:string,1:string}>
	 */
	public static function clean( array $headers ): array {
		$out = array();
		foreach ( $headers as $header ) {
			if ( ! is_array( $header ) || ! isset( $header[0], $header[1] ) || ! is_string( $header[0] ) || ! is_scalar( $header[1] ) ) {
				continue;
			}
			$name  = $header[0];
			$value = (string) $header[1];
			if ( ! preg_match( '/^[A-Za-z0-9-]{1,64}$/', $name ) || preg_match( '/[\r\n\x00]/', $value ) ) {
				continue;
			}
			$out[] = array( $name, $value );
		}

		return $out;
	}

	/**
	 * Capability needed to manage the plugin.
	 */
	public static function capability(): string {
		/**
		 * Filters the capability needed to change the settings, scan and see reports.
		 *
		 * @param string $capability Capability, `manage_options` by default.
		 */
		$capability = apply_filters( 'security_headers_capability', 'manage_options' );

		return is_string( $capability ) && '' !== $capability ? $capability : 'manage_options';
	}

	/**
	 * Main plugin file.
	 */
	public function file(): string {
		return $this->file;
	}
}
