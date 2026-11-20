<?php
/**
 * WP-CLI command.
 *
 * @package Saizul\SecurityHeaders
 */

namespace Saizul\SecurityHeaders\Cli;

use Saizul\SecurityHeaders\Export;
use Saizul\SecurityHeaders\Grader;
use Saizul\SecurityHeaders\HeaderBuilder;
use Saizul\SecurityHeaders\Hsts;
use Saizul\SecurityHeaders\Plugin;
use Saizul\SecurityHeaders\Reports\Endpoint;
use Saizul\SecurityHeaders\Scanner;
use Saizul\SecurityHeaders\Settings;

defined( 'ABSPATH' ) || exit;

/**
 * Show the configured security headers and grade a live page.
 *
 * ## EXAMPLES
 *
 *     wp security-headers status
 *     wp security-headers scan
 *     wp security-headers scan --url=https://example.com/shop/ --fail-under=B
 *     wp security-headers export --server=nginx
 */
final class Command {

	/**
	 * Plugin.
	 *
	 * @var Plugin
	 */
	private $plugin;

	/**
	 * Scanner.
	 *
	 * @var Scanner
	 */
	private $scanner;

	/**
	 * Constructor.
	 *
	 * @param Plugin       $plugin  Plugin.
	 * @param Scanner|null $scanner Scanner.
	 */
	public function __construct( Plugin $plugin, ?Scanner $scanner = null ) {
		$this->plugin  = $plugin;
		$this->scanner = $scanner ?? new Scanner();
	}

	/**
	 * Show the headers the plugin sends and any configuration warnings.
	 *
	 * ## OPTIONS
	 *
	 * [--area=<area>]
	 * : Which kind of request to show.
	 * ---
	 * default: front
	 * options:
	 *   - front
	 *   - admin
	 *   - login
	 * ---
	 *
	 * [--format=<format>]
	 * : Output format.
	 * ---
	 * default: table
	 * options:
	 *   - table
	 *   - json
	 * ---
	 *
	 * ## EXAMPLES
	 *
	 *     wp security-headers status
	 *     wp security-headers status --format=json
	 *
	 * @param string[]             $args       Positional arguments.
	 * @param array<string,string> $assoc_args Options.
	 */
	public function status( $args, $assoc_args ): void {
		$settings = $this->plugin->settings();
		$area     = $assoc_args['area'] ?? HeaderBuilder::AREA_FRONT;
		if ( ! in_array( $area, array( HeaderBuilder::AREA_FRONT, HeaderBuilder::AREA_ADMIN, HeaderBuilder::AREA_LOGIN ), true ) ) {
			\WP_CLI::error( 'Unknown area. Use front, admin or login.' );
		}
		$https   = 0 === stripos( home_url( '/' ), 'https://' );
		$headers = $this->plugin->headers( $area, $https );
		$sent    = HeaderBuilder::AREA_FRONT === $area
			|| ( HeaderBuilder::AREA_ADMIN === $area && ! empty( $settings['apply_admin'] ) )
			|| ( HeaderBuilder::AREA_LOGIN === $area && ! empty( $settings['apply_login'] ) );
		if ( ! $sent ) {
			$headers = array();
		}

		$warnings = array();
		foreach ( Hsts::warnings( $settings, home_url( '/' ) ) as $item ) {
			$warnings[] = 'HSTS: ' . $item['message'];
		}
		if ( Settings::CSP_OFF !== $settings['csp_mode'] ) {
			foreach ( HeaderBuilder::csp( $settings, ! empty( $settings['csp_nonce'] ) ? 'cli-placeholder-nonce' : null, Endpoint::url() )->warnings() as $item ) {
				if ( 'info' !== $item['severity'] ) {
					$warnings[] = 'CSP: ' . $item['message'];
				}
			}
		}

		if ( 'json' === ( $assoc_args['format'] ?? 'table' ) ) {
			\WP_CLI::line(
				(string) wp_json_encode(
					array(
						'area'     => $area,
						'https'    => $https,
						'csp_mode' => (string) $settings['csp_mode'],
						'headers'  => array_map(
							static function ( $header ) {
								return array(
									'name'  => $header[0],
									'value' => $header[1],
								);
							},
							$headers
						),
						'warnings' => $warnings,
					)
				)
			);
			return;
		}

		if ( array() === $headers ) {
			\WP_CLI::warning( 'No headers are sent for this area.' );
		} else {
			\WP_CLI\Utils\format_items(
				'table',
				array_map(
					static function ( $header ) {
						return array(
							'header' => $header[0],
							'value'  => $header[1],
						);
					},
					$headers
				),
				array( 'header', 'value' )
			);
		}
		if ( ! $https ) {
			\WP_CLI::warning( 'The site address is not https://, so Strict-Transport-Security is not sent.' );
		}
		foreach ( $warnings as $warning ) {
			\WP_CLI::warning( $warning );
		}
	}

	/**
	 * Load a page from this server and grade its security headers (A to F).
	 *
	 * ## OPTIONS
	 *
	 * [--url=<url>]
	 * : Page to scan. Defaults to the home page.
	 *
	 * [--fail-under=<grade>]
	 * : Exit with status 1 when the grade is worse than this (for CI and monitoring).
	 * ---
	 * options:
	 *   - A
	 *   - B
	 *   - C
	 *   - D
	 *   - E
	 * ---
	 *
	 * [--format=<format>]
	 * : Output format.
	 * ---
	 * default: table
	 * options:
	 *   - table
	 *   - json
	 * ---
	 *
	 * ## EXAMPLES
	 *
	 *     wp security-headers scan
	 *     wp security-headers scan --url=https://example.com/checkout/ --format=json
	 *     wp security-headers scan --fail-under=B
	 *
	 * @param string[]             $args       Positional arguments.
	 * @param array<string,string> $assoc_args Options.
	 */
	public function scan( $args, $assoc_args ): void {
		$url    = (string) ( $assoc_args['url'] ?? '' );
		$result = '' === $url ? $this->scanner->scan_and_store() : $this->scanner->scan( $url );
		if ( is_wp_error( $result ) ) {
			\WP_CLI::error( $result->get_error_message() );
			return;
		}
		$grade = (string) $result['result']['grade'];

		if ( 'json' === ( $assoc_args['format'] ?? 'table' ) ) {
			\WP_CLI::line(
				(string) wp_json_encode(
					array(
						'url'      => $result['url'],
						'status'   => $result['status'],
						'grade'    => $grade,
						'score'    => $result['result']['score'],
						'max'      => $result['result']['max'],
						'findings' => $result['result']['findings'],
					)
				)
			);
		} else {
			$rows = array();
			foreach ( $result['result']['findings'] as $finding ) {
				$rows[] = array(
					'header' => $finding['header'],
					'result' => $finding['status'],
					'points' => $finding['max'] > 0 ? $finding['score'] . '/' . $finding['max'] : '-',
					'fix'    => '' !== $finding['fix'] ? $finding['fix'] : $finding['message'],
				);
			}
			\WP_CLI\Utils\format_items( 'table', $rows, array( 'header', 'result', 'points', 'fix' ) );
			\WP_CLI::line( sprintf( 'Grade %s (%d/%d) for %s', $grade, $result['result']['score'], $result['result']['max'], $result['url'] ) );
		}

		if ( isset( $assoc_args['fail-under'] ) ) {
			$min = strtoupper( (string) $assoc_args['fail-under'] );
			if ( ! isset( Grader::GRADES[ $min ] ) ) {
				\WP_CLI::error( 'Unknown grade for --fail-under. Use A, B, C, D or E.' );
			}
			if ( Grader::GRADES[ $grade ] < Grader::GRADES[ $min ] ) {
				\WP_CLI::halt( 1 );
			}
		}
	}

	/**
	 * Print the headers as nginx or Apache configuration.
	 *
	 * ## OPTIONS
	 *
	 * [--server=<server>]
	 * : Web server.
	 * ---
	 * default: nginx
	 * options:
	 *   - nginx
	 *   - apache
	 * ---
	 *
	 * ## EXAMPLES
	 *
	 *     wp security-headers export --server=nginx > /etc/nginx/snippets/security-headers.conf
	 *     wp security-headers export --server=apache
	 *
	 * @param string[]             $args       Positional arguments.
	 * @param array<string,string> $assoc_args Options.
	 */
	public function export( $args, $assoc_args ): void {
		$server = $assoc_args['server'] ?? Export::NGINX;
		if ( ! in_array( $server, array( Export::NGINX, Export::APACHE ), true ) ) {
			\WP_CLI::error( 'Unknown server. Use nginx or apache.' );
		}
		$settings = $this->plugin->settings();
		\WP_CLI::line( rtrim( Export::render( $server, Export::headers( $settings, Endpoint::url() ), Export::notes( $settings ) ) ) );
	}
}
