<?php
/**
 * Scan, Violations and Export tabs.
 *
 * @package Saizul\SecurityHeaders
 */

namespace Saizul\SecurityHeaders\Admin;

use Saizul\SecurityHeaders\Export;
use Saizul\SecurityHeaders\Plugin;
use Saizul\SecurityHeaders\Reports\Endpoint;
use Saizul\SecurityHeaders\Reports\Suggest;
use Saizul\SecurityHeaders\Scanner;
use Saizul\SecurityHeaders\Settings;

defined( 'ABSPATH' ) || exit;

/**
 * Tool tabs and their admin-post handlers. Each handler checks the
 * capability and its own nonce.
 */
final class Tools {

	const SCAN  = 'wp_security_headers_scan';
	const CLEAR = 'wp_security_headers_clear';

	const ERROR_TRANSIENT = 'wpsh_scan_error_';

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
	 * Register hooks.
	 */
	public function register(): void {
		add_action( 'admin_post_' . self::SCAN, array( $this, 'handle_scan' ) );
		add_action( 'admin_post_' . self::CLEAR, array( $this, 'handle_clear' ) );
		add_action( 'admin_init', array( $this->plugin->store(), 'maybe_install' ) );
	}

	/**
	 * Print a tab.
	 *
	 * @param string $tab scan, violations or export.
	 */
	public function render_tab( string $tab ): void {
		if ( ! current_user_can( Plugin::capability() ) ) {
			return;
		}
		if ( 'scan' === $tab ) {
			$this->render_scan();
		} elseif ( 'violations' === $tab ) {
			$this->render_violations();
		} elseif ( 'export' === $tab ) {
			$this->render_export();
		}
	}

	/**
	 * Scan tab.
	 */
	private function render_scan(): void {
		$error_key = self::ERROR_TRANSIENT . get_current_user_id();
		$error     = (string) get_transient( $error_key );
		if ( '' !== $error ) {
			delete_transient( $error_key );
		}
		$last = Scanner::last();
		?>
		<p><?php echo esc_html__( 'The scan loads your home page from the server, like a visitor would, and grades the security headers it receives. Page caches and CDNs can add or strip headers, so this shows what visitors really get.', 'wp-security-headers' ); ?></p>
		<form action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" method="post">
			<input type="hidden" name="action" value="<?php echo esc_attr( self::SCAN ); ?>">
			<?php wp_nonce_field( self::SCAN ); ?>
			<?php submit_button( __( 'Scan my site', 'wp-security-headers' ), 'primary', 'submit', false ); ?>
		</form>
		<?php
		if ( '' !== $error ) {
			echo '<div class="notice notice-error inline"><p>' . esc_html( $error ) . '</p></div>';
		}
		if ( null === $last ) {
			return;
		}
		$result = $last['result'];
		printf(
			'<h2>%1$s <span style="font-size:2em;vertical-align:middle;margin-left:.3em">%2$s</span></h2><p>%3$s</p>',
			esc_html__( 'Grade', 'wp-security-headers' ),
			esc_html( (string) $result['grade'] ),
			esc_html(
				sprintf(
					/* translators: 1: points, 2: maximum points, 3: URL, 4: date and time. */
					__( '%1$d of %2$d points for %3$s, scanned %4$s.', 'wp-security-headers' ),
					(int) $result['score'],
					(int) $result['max'],
					(string) $last['url'],
					wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), (int) $last['time'] )
				)
			)
		);
		$status_labels = array(
			'pass' => __( 'Pass', 'wp-security-headers' ),
			'warn' => __( 'Improve', 'wp-security-headers' ),
			'fail' => __( 'Missing', 'wp-security-headers' ),
			'info' => __( 'Info', 'wp-security-headers' ),
		);
		?>
		<table class="widefat striped" style="max-width:1100px">
			<thead><tr>
				<th scope="col"><?php echo esc_html__( 'Header', 'wp-security-headers' ); ?></th>
				<th scope="col"><?php echo esc_html__( 'Result', 'wp-security-headers' ); ?></th>
				<th scope="col"><?php echo esc_html__( 'Points', 'wp-security-headers' ); ?></th>
				<th scope="col"><?php echo esc_html__( 'Details and fix', 'wp-security-headers' ); ?></th>
			</tr></thead>
			<tbody>
			<?php foreach ( (array) $result['findings'] as $finding ) : ?>
				<tr>
					<td><code><?php echo esc_html( (string) $finding['header'] ); ?></code></td>
					<td><?php echo esc_html( $status_labels[ $finding['status'] ] ?? (string) $finding['status'] ); ?></td>
					<td><?php echo esc_html( $finding['max'] > 0 ? $finding['score'] . ' / ' . $finding['max'] : '-' ); ?></td>
					<td><?php echo esc_html( (string) $finding['message'] ); ?>
						<?php if ( '' !== (string) $finding['fix'] ) : ?>
							<br><strong><?php echo esc_html__( 'Fix:', 'wp-security-headers' ); ?></strong> <?php echo esc_html( (string) $finding['fix'] ); ?>
						<?php endif; ?>
					</td>
				</tr>
			<?php endforeach; ?>
			</tbody>
		</table>
		<?php
	}

	/**
	 * Violations tab.
	 */
	private function render_violations(): void {
		$settings = $this->plugin->settings();
		$store    = $this->plugin->store();
		$store->maybe_install();
		$count = $store->count();
		$rows  = $store->rows( 200 );

		if ( Settings::CSP_OFF === $settings['csp_mode'] || empty( $settings['csp_report'] ) ) {
			echo '<div class="notice notice-info inline"><p>' . esc_html__( 'Reports arrive while the CSP mode is Report-Only or Enforce and "Send violation reports" is on.', 'wp-security-headers' ) . '</p></div>';
		}
		printf(
			'<p>%s</p>',
			esc_html(
				sprintf(
					/* translators: 1: number of violations, 2: maximum kept. */
					_n( '%1$d distinct violation stored (at most %2$d are kept; the least recently seen are removed first).', '%1$d distinct violations stored (at most %2$d are kept; the least recently seen are removed first).', $count, 'wp-security-headers' ),
					$count,
					(int) $settings['report_cap']
				)
			)
		);
		if ( array() === $rows ) {
			echo '<p><em>' . esc_html__( 'No violations yet. Browse your site with the policy in Report-Only mode, then come back.', 'wp-security-headers' ) . '</em></p>';
			return;
		}
		?>
		<table class="widefat striped">
			<thead><tr>
				<th scope="col"><?php echo esc_html__( 'Directive', 'wp-security-headers' ); ?></th>
				<th scope="col"><?php echo esc_html__( 'Blocked', 'wp-security-headers' ); ?></th>
				<th scope="col"><?php echo esc_html__( 'Hits', 'wp-security-headers' ); ?></th>
				<th scope="col"><?php echo esc_html__( 'Last page and source', 'wp-security-headers' ); ?></th>
				<th scope="col"><?php echo esc_html__( 'Suggestion', 'wp-security-headers' ); ?></th>
			</tr></thead>
			<tbody>
			<?php foreach ( $rows as $row ) : ?>
				<tr>
					<td><code><?php echo esc_html( (string) $row['directive'] ); ?></code><?php echo 'report' === $row['disposition'] ? '<br><span class="description">' . esc_html__( 'report-only', 'wp-security-headers' ) . '</span>' : ''; ?></td>
					<td><code><?php echo esc_html( '' !== (string) $row['blocked_uri'] ? (string) $row['blocked_uri'] : '-' ); ?></code>
						<?php if ( '' !== (string) $row['sample'] ) : ?>
							<br><span class="description"><?php echo esc_html( (string) $row['sample'] ); ?></span>
						<?php endif; ?>
					</td>
					<td><?php echo esc_html( (string) (int) $row['hits'] ); ?><br><span class="description"><?php echo esc_html( (string) $row['last_seen'] ); ?> UTC</span></td>
					<td><?php echo esc_html( (string) $row['document_uri'] ); ?>
						<?php if ( '' !== (string) $row['source_file'] ) : ?>
							<br><span class="description"><?php echo esc_html( $row['source_file'] . ( (int) $row['line_number'] > 0 ? ':' . (int) $row['line_number'] : '' ) ); ?></span>
						<?php endif; ?>
					</td>
					<td><?php echo esc_html( Suggest::for_violation( $row ) ); ?></td>
				</tr>
			<?php endforeach; ?>
			</tbody>
		</table>
		<form action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" method="post" style="margin-top:1em">
			<input type="hidden" name="action" value="<?php echo esc_attr( self::CLEAR ); ?>">
			<?php wp_nonce_field( self::CLEAR ); ?>
			<?php submit_button( __( 'Delete all stored violations', 'wp-security-headers' ), 'delete', 'submit', false ); ?>
		</form>
		<?php
	}

	/**
	 * Export tab.
	 */
	private function render_export(): void {
		$settings = $this->plugin->settings();
		$headers  = Export::headers( $settings, Endpoint::url() );
		$notes    = Export::notes( $settings );
		?>
		<p><?php echo esc_html__( 'Prefer server configuration? Copy these snippets. They match the current settings for HTTPS requests. Server headers also cover static files and pages served by a full-page cache without PHP.', 'wp-security-headers' ); ?></p>
		<h2><label for="wpsh-export-nginx">nginx</label></h2>
		<textarea id="wpsh-export-nginx" class="large-text code" rows="12" readonly><?php echo esc_textarea( Export::nginx( $headers, $notes ) ); ?></textarea>
		<h2><label for="wpsh-export-apache">Apache</label></h2>
		<textarea id="wpsh-export-apache" class="large-text code" rows="14" readonly><?php echo esc_textarea( Export::apache( $headers, $notes ) ); ?></textarea>
		<?php
	}

	/**
	 * "Scan my site".
	 */
	public function handle_scan(): void {
		if ( ! current_user_can( Plugin::capability() ) ) {
			wp_die( esc_html__( 'You are not allowed to do this.', 'wp-security-headers' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( self::SCAN );

		$result = $this->scanner->scan_and_store();
		if ( is_wp_error( $result ) ) {
			set_transient( self::ERROR_TRANSIENT . get_current_user_id(), $result->get_error_message(), 300 );
		}
		wp_safe_redirect( SettingsPage::url( array( 'tab' => 'scan' ) ) );
		$this->finish();
	}

	/**
	 * "Delete all stored violations".
	 */
	public function handle_clear(): void {
		if ( ! current_user_can( Plugin::capability() ) ) {
			wp_die( esc_html__( 'You are not allowed to do this.', 'wp-security-headers' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( self::CLEAR );

		$this->plugin->store()->clear();
		wp_safe_redirect( SettingsPage::url( array( 'tab' => 'violations' ) ) );
		$this->finish();
	}

	/**
	 * End the request after a redirect (tests return false from the filter).
	 */
	private function finish(): void {
		/**
		 * Whether to exit after a redirect. Tests return false.
		 *
		 * @param bool $exit Exit.
		 */
		if ( apply_filters( 'security_headers_exit_after_redirect', true ) ) {
			exit;
		}
	}
}
