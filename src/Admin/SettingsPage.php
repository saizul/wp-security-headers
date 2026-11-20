<?php
/**
 * Settings > Security Headers screen.
 *
 * @package Saizul\SecurityHeaders
 */

namespace Saizul\SecurityHeaders\Admin;

use Saizul\SecurityHeaders\Csp\Presets;
use Saizul\SecurityHeaders\HeaderBuilder;
use Saizul\SecurityHeaders\Hsts;
use Saizul\SecurityHeaders\PermissionsPolicy;
use Saizul\SecurityHeaders\Plugin;
use Saizul\SecurityHeaders\Reports\Endpoint;
use Saizul\SecurityHeaders\Sanitizer;
use Saizul\SecurityHeaders\Settings;

defined( 'ABSPATH' ) || exit;

/**
 * The screen has four tabs. "Settings" is one form that posts to
 * options.php (nonce and capability checked by core, values passed through
 * Settings::sanitize()). "Scan", "Violations" and "Export" are rendered by
 * Tools.
 */
final class SettingsPage {

	const SLUG  = 'wp-security-headers';
	const GROUP = 'wp_security_headers';

	/**
	 * Plugin.
	 *
	 * @var Plugin
	 */
	private $plugin;

	/**
	 * Constructor.
	 *
	 * @param Plugin $plugin Plugin.
	 */
	public function __construct( Plugin $plugin ) {
		$this->plugin = $plugin;
	}

	/**
	 * Register hooks.
	 */
	public function register(): void {
		add_action( 'admin_menu', array( $this, 'add_page' ) );
		add_action( 'admin_init', array( $this, 'register_settings' ) );
		add_filter( 'option_page_capability_' . self::GROUP, array( Plugin::class, 'capability' ) );
		add_filter( 'plugin_action_links_' . plugin_basename( $this->plugin->file() ), array( $this, 'action_links' ) );
	}

	/**
	 * URL of the screen.
	 *
	 * @param array<string,string> $args Extra query arguments.
	 */
	public static function url( array $args = array() ): string {
		return add_query_arg( array_merge( array( 'page' => self::SLUG ), $args ), admin_url( 'options-general.php' ) );
	}

	/**
	 * Tabs.
	 *
	 * @return array<string,string>
	 */
	public static function tabs(): array {
		return array(
			'settings'   => __( 'Settings', 'wp-security-headers' ),
			'scan'       => __( 'Scan', 'wp-security-headers' ),
			'violations' => __( 'Violations', 'wp-security-headers' ),
			'export'     => __( 'Export', 'wp-security-headers' ),
		);
	}

	/**
	 * Current tab.
	 */
	public static function current_tab(): string {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Display only.
		$tab = isset( $_GET['tab'] ) ? sanitize_key( wp_unslash( $_GET['tab'] ) ) : 'settings';

		return array_key_exists( $tab, self::tabs() ) ? $tab : 'settings';
	}

	/**
	 * Add Settings > Security Headers.
	 */
	public function add_page(): void {
		add_options_page(
			__( 'Security Headers', 'wp-security-headers' ),
			__( 'Security Headers', 'wp-security-headers' ),
			Plugin::capability(),
			self::SLUG,
			array( $this, 'render' )
		);
	}

	/**
	 * Add a Settings link on the Plugins screen.
	 *
	 * @param mixed $links Links.
	 * @return mixed
	 */
	public function action_links( $links ) {
		if ( ! is_array( $links ) || ! current_user_can( Plugin::capability() ) ) {
			return $links;
		}
		array_unshift( $links, '<a href="' . esc_url( self::url() ) . '">' . esc_html__( 'Settings', 'wp-security-headers' ) . '</a>' );

		return $links;
	}

	/**
	 * Register the setting.
	 */
	public function register_settings(): void {
		register_setting(
			self::GROUP,
			Settings::OPTION,
			array(
				'type'              => 'array',
				'sanitize_callback' => array( Settings::class, 'sanitize' ),
				'default'           => Settings::defaults(),
				'show_in_rest'      => false,
			)
		);
	}

	/**
	 * Name attribute of a field.
	 *
	 * @param string $key  Setting key.
	 * @param string $tail Extra brackets, e.g. `[camera][on]`.
	 */
	private static function name( string $key, string $tail = '' ): string {
		return Settings::OPTION . '[' . $key . ']' . $tail;
	}

	/**
	 * Print the screen.
	 */
	public function render(): void {
		if ( ! current_user_can( Plugin::capability() ) ) {
			return;
		}
		$tab = self::current_tab();
		echo '<div class="wrap"><h1>' . esc_html( get_admin_page_title() ) . '</h1>';
		echo '<nav class="nav-tab-wrapper" aria-label="' . esc_attr__( 'Security Headers sections', 'wp-security-headers' ) . '">';
		foreach ( self::tabs() as $slug => $label ) {
			printf(
				'<a href="%1$s" class="nav-tab%2$s"%3$s>%4$s</a>',
				esc_url( self::url( array( 'tab' => $slug ) ) ),
				$slug === $tab ? ' nav-tab-active' : '',
				$slug === $tab ? ' aria-current="page"' : '',
				esc_html( $label )
			);
		}
		echo '</nav>';

		if ( 'settings' === $tab ) {
			$this->render_settings();
		} else {
			( new Tools( $this->plugin ) )->render_tab( $tab );
		}
		echo '</div>';
	}

	/**
	 * Print a list of warnings.
	 *
	 * @param array<int,array<string,string>> $items Items with severity and message.
	 */
	public static function warnings_list( array $items ): void {
		if ( array() === $items ) {
			return;
		}
		$labels = array(
			'high'   => __( 'Important', 'wp-security-headers' ),
			'medium' => __( 'Check', 'wp-security-headers' ),
			'low'    => __( 'Tip', 'wp-security-headers' ),
			'info'   => __( 'Note', 'wp-security-headers' ),
		);
		echo '<ul class="wpsh-warnings">';
		foreach ( $items as $item ) {
			$severity = $item['severity'] ?? 'info';
			printf(
				'<li class="wpsh-%1$s"><strong>%2$s:</strong> %3$s</li>',
				esc_attr( $severity ),
				esc_html( $labels[ $severity ] ?? $labels['info'] ),
				esc_html( $item['message'] ?? '' )
			);
		}
		echo '</ul>';
	}

	/**
	 * Print a select.
	 *
	 * @param string               $key     Setting key.
	 * @param array<string,string> $choices Value => label.
	 * @param string               $current Current value.
	 */
	private static function select( string $key, array $choices, string $current ): void {
		printf( '<select id="wpsh-%1$s" name="%2$s">', esc_attr( $key ), esc_attr( self::name( $key ) ) );
		foreach ( $choices as $value => $label ) {
			printf( '<option value="%1$s"%2$s>%3$s</option>', esc_attr( (string) $value ), selected( (string) $value, $current, false ), esc_html( $label ) );
		}
		echo '</select>';
	}

	/**
	 * Print a checkbox.
	 *
	 * @param string $key     Setting key.
	 * @param bool   $checked State.
	 * @param string $label   Label.
	 */
	private static function checkbox( string $key, bool $checked, string $label ): void {
		printf(
			'<label><input type="checkbox" name="%1$s" value="1"%2$s> %3$s</label>',
			esc_attr( self::name( $key ) ),
			checked( $checked, true, false ),
			esc_html( $label )
		);
	}

	/**
	 * Settings form.
	 */
	private function render_settings(): void {
		$s = $this->plugin->settings();
		?>
		<style>
			.wpsh-warnings{margin:.5em 0 1em}.wpsh-warnings li{margin:.25em 0;padding-left:.5em;border-left:4px solid #72aee6}
			.wpsh-warnings .wpsh-high{border-color:#d63638}.wpsh-warnings .wpsh-medium{border-color:#dba617}
			.wpsh-perm td,.wpsh-perm th{padding:4px 8px}.wpsh-preview{white-space:pre-wrap;word-break:break-all;background:#f6f7f7;padding:8px;border:1px solid #dcdcde}
		</style>
		<form action="options.php" method="post">
			<?php settings_fields( self::GROUP ); ?>

			<h2><?php echo esc_html__( 'Where to send headers', 'wp-security-headers' ); ?></h2>
			<table class="form-table" role="presentation">
				<tr><th scope="row"><?php echo esc_html__( 'Areas', 'wp-security-headers' ); ?></th><td>
					<p><em><?php echo esc_html__( 'The front end always gets the headers.', 'wp-security-headers' ); ?></em></p>
					<?php self::checkbox( 'apply_admin', (bool) $s['apply_admin'], __( 'Also send them in wp-admin (without Content-Security-Policy)', 'wp-security-headers' ) ); ?><br>
					<?php self::checkbox( 'apply_login', (bool) $s['apply_login'], __( 'Also send them on wp-login.php (without Content-Security-Policy)', 'wp-security-headers' ) ); ?><br>
					<?php self::checkbox( 'remove_powered_by', (bool) $s['remove_powered_by'], __( 'Remove the X-Powered-By header (hides the PHP version)', 'wp-security-headers' ) ); ?>
				</td></tr>
			</table>

			<h2><?php echo esc_html__( 'Strict-Transport-Security (HSTS)', 'wp-security-headers' ); ?></h2>
			<table class="form-table" role="presentation">
				<tr><th scope="row"><?php echo esc_html__( 'HSTS', 'wp-security-headers' ); ?></th><td>
					<?php self::checkbox( 'hsts_enabled', (bool) $s['hsts_enabled'], __( 'Tell browsers to use HTTPS only (sent on HTTPS requests)', 'wp-security-headers' ) ); ?>
				</td></tr>
				<tr><th scope="row"><label for="wpsh-hsts_max_age"><?php echo esc_html__( 'max-age', 'wp-security-headers' ); ?></label></th><td>
					<?php
					$ages = array();
					foreach ( Hsts::max_age_choices() as $seconds => $label ) {
						$ages[ (string) $seconds ] = $label;
					}
					if ( ! isset( $ages[ (string) $s['hsts_max_age'] ] ) ) {
						/* translators: %d: number of seconds. */
						$ages[ (string) $s['hsts_max_age'] ] = sprintf( __( '%d seconds', 'wp-security-headers' ), (int) $s['hsts_max_age'] );
					}
					self::select( 'hsts_max_age', $ages, (string) $s['hsts_max_age'] );
					?>
				</td></tr>
				<tr><th scope="row"><?php echo esc_html__( 'Options', 'wp-security-headers' ); ?></th><td>
					<?php self::checkbox( 'hsts_include_subdomains', (bool) $s['hsts_include_subdomains'], __( 'includeSubDomains', 'wp-security-headers' ) ); ?><br>
					<?php self::checkbox( 'hsts_preload', (bool) $s['hsts_preload'], __( 'preload (also turns on includeSubDomains and at least 1 year)', 'wp-security-headers' ) ); ?>
					<?php self::warnings_list( Hsts::warnings( $s, home_url( '/' ) ) ); ?>
				</td></tr>
			</table>

			<h2><?php echo esc_html__( 'Basic headers', 'wp-security-headers' ); ?></h2>
			<table class="form-table" role="presentation">
				<tr><th scope="row"><?php echo esc_html__( 'X-Content-Type-Options', 'wp-security-headers' ); ?></th><td>
					<?php self::checkbox( 'nosniff', (bool) $s['nosniff'], __( 'nosniff: browsers must not guess content types', 'wp-security-headers' ) ); ?>
				</td></tr>
				<tr><th scope="row"><label for="wpsh-referrer_policy"><?php echo esc_html__( 'Referrer-Policy', 'wp-security-headers' ); ?></label></th><td>
					<?php self::select( 'referrer_policy', array_merge( array( '' => __( 'Not sent', 'wp-security-headers' ) ), array_combine( Sanitizer::REFERRER_POLICIES, Sanitizer::REFERRER_POLICIES ) ), (string) $s['referrer_policy'] ); ?>
					<p class="description"><?php echo esc_html__( 'strict-origin-when-cross-origin is the recommended value.', 'wp-security-headers' ); ?></p>
				</td></tr>
				<tr><th scope="row"><label for="wpsh-framing"><?php echo esc_html__( 'Framing', 'wp-security-headers' ); ?></label></th><td>
					<?php
					self::select(
						'framing',
						array(
							'sameorigin' => __( 'Same origin only (X-Frame-Options: SAMEORIGIN, frame-ancestors \'self\')', 'wp-security-headers' ),
							'deny'       => __( 'Nobody (X-Frame-Options: DENY, frame-ancestors \'none\')', 'wp-security-headers' ),
							'off'        => __( 'Not restricted', 'wp-security-headers' ),
						),
						(string) $s['framing']
					);
					?>
					<p><label for="wpsh-frame_ancestors"><?php echo esc_html__( 'Allowed framing origins (with "Same origin only"), one per line:', 'wp-security-headers' ); ?></label><br>
					<textarea id="wpsh-frame_ancestors" name="<?php echo esc_attr( self::name( 'frame_ancestors' ) ); ?>" rows="3" cols="50" class="code" placeholder="https://partner.example"><?php echo esc_textarea( implode( "\n", (array) $s['frame_ancestors'] ) ); ?></textarea></p>
				</td></tr>
				<tr><th scope="row"><label for="wpsh-coop"><?php echo esc_html__( 'Cross-Origin-Opener-Policy', 'wp-security-headers' ); ?></label></th><td>
					<?php self::select( 'coop', array_merge( array( '' => __( 'Not sent', 'wp-security-headers' ) ), array_combine( Sanitizer::COOP, Sanitizer::COOP ) ), (string) $s['coop'] ); ?>
					<p class="description"><?php echo esc_html__( 'same-origin-allow-popups keeps payment and social login popups working. same-origin is stricter.', 'wp-security-headers' ); ?></p>
				</td></tr>
				<tr><th scope="row"><label for="wpsh-corp"><?php echo esc_html__( 'Cross-Origin-Resource-Policy', 'wp-security-headers' ); ?></label></th><td>
					<?php self::select( 'corp', array_merge( array( '' => __( 'Not sent', 'wp-security-headers' ) ), array_combine( Sanitizer::CORP, Sanitizer::CORP ) ), (string) $s['corp'] ); ?>
					<p class="description"><?php echo esc_html__( 'Applies to responses WordPress generates (pages, feeds, REST). Static files are served by the web server.', 'wp-security-headers' ); ?></p>
				</td></tr>
			</table>

			<h2><?php echo esc_html__( 'Permissions-Policy', 'wp-security-headers' ); ?></h2>
			<p><?php echo esc_html__( 'Tick a feature to restrict it. "Nobody" switches it off for the page and every embed; "This site only" allows your own pages but not embedded content.', 'wp-security-headers' ); ?></p>
			<table class="widefat striped wpsh-perm" style="max-width:900px">
				<thead><tr>
					<th scope="col"><?php echo esc_html__( 'Restrict', 'wp-security-headers' ); ?></th>
					<th scope="col"><?php echo esc_html__( 'Feature', 'wp-security-headers' ); ?></th>
					<th scope="col"><?php echo esc_html__( 'Allowed for', 'wp-security-headers' ); ?></th>
				</tr></thead>
				<tbody>
				<?php
				foreach ( PermissionsPolicy::features() as $feature => $description ) {
					$current = $s['permissions'][ $feature ] ?? '';
					$id      = 'wpsh-perm-' . $feature;
					printf(
						'<tr><td><input type="checkbox" id="%1$s" name="%2$s" value="1"%3$s></td><td><label for="%1$s"><code>%4$s</code></label><br><span class="description">%5$s</span></td><td><select name="%6$s" aria-label="%7$s"><option value="none"%8$s>%9$s</option><option value="self"%10$s>%11$s</option></select></td></tr>',
						esc_attr( $id ),
						esc_attr( self::name( 'permissions', '[' . $feature . '][on]' ) ),
						checked( '' !== $current, true, false ),
						esc_html( $feature ),
						esc_html( $description ),
						esc_attr( self::name( 'permissions', '[' . $feature . '][allow]' ) ),
						/* translators: %s: feature name. */
						esc_attr( sprintf( __( 'Who may use %s', 'wp-security-headers' ), $feature ) ),
						selected( PermissionsPolicy::SELF !== $current, true, false ),
						esc_html__( 'Nobody', 'wp-security-headers' ),
						selected( PermissionsPolicy::SELF === $current, true, false ),
						esc_html__( 'This site only', 'wp-security-headers' )
					);
				}
				?>
				</tbody>
			</table>

			<?php $this->render_csp( $s ); ?>

			<?php submit_button(); ?>
		</form>
		<?php
	}

	/**
	 * CSP builder section.
	 *
	 * @param array<string,mixed> $s Settings.
	 */
	private function render_csp( array $s ): void {
		$modes  = array(
			Settings::CSP_OFF         => __( 'Off', 'wp-security-headers' ),
			Settings::CSP_REPORT_ONLY => __( 'Report-Only: nothing is blocked, violations are reported (start here)', 'wp-security-headers' ),
			Settings::CSP_ENFORCE     => __( 'Enforce: violations are blocked', 'wp-security-headers' ),
		);
		$policy = HeaderBuilder::csp( $s, ! empty( $s['csp_nonce'] ) ? 'NONCE-PLACEHOLDER-1234' : null, Endpoint::url() );
		?>
		<h2><?php echo esc_html__( 'Content-Security-Policy', 'wp-security-headers' ); ?></h2>
		<table class="form-table" role="presentation">
			<tr><th scope="row"><?php echo esc_html__( 'Mode', 'wp-security-headers' ); ?></th><td><fieldset>
				<?php
				foreach ( $modes as $value => $label ) {
					printf(
						'<label><input type="radio" name="%1$s" value="%2$s"%3$s> %4$s</label><br>',
						esc_attr( self::name( 'csp_mode' ) ),
						esc_attr( $value ),
						checked( (string) $s['csp_mode'], $value, false ),
						esc_html( $label )
					);
				}
				?>
				<p class="description"><?php echo esc_html__( 'The policy is only sent on the front end. wp-admin and the block editor need inline scripts and are left alone.', 'wp-security-headers' ); ?></p>
			</fieldset></td></tr>
			<tr><th scope="row"><label for="wpsh-csp_preset"><?php echo esc_html__( 'Preset', 'wp-security-headers' ); ?></label></th><td>
				<?php self::select( 'csp_preset', Presets::labels(), (string) $s['csp_preset'] ); ?>
				<button type="submit" class="button" name="<?php echo esc_attr( self::name( 'apply_preset' ) ); ?>" value="1"><?php echo esc_html__( 'Load preset (replaces the directives below)', 'wp-security-headers' ); ?></button>
			</td></tr>
			<tr><th scope="row"><?php echo esc_html__( 'Options', 'wp-security-headers' ); ?></th><td>
				<?php self::checkbox( 'csp_nonce', (bool) $s['csp_nonce'], __( 'Add a nonce to script-src and to every script WordPress prints (wp_script_attributes / wp_inline_script_attributes)', 'wp-security-headers' ) ); ?><br>
				<?php self::checkbox( 'csp_upgrade_insecure', (bool) $s['csp_upgrade_insecure'], __( 'upgrade-insecure-requests (load http:// resources over https://)', 'wp-security-headers' ) ); ?><br>
				<?php self::checkbox( 'csp_report', (bool) $s['csp_report'], __( 'Send violation reports to this site (report-uri and report-to)', 'wp-security-headers' ) ); ?>
				<p class="description"><code><?php echo esc_html( Endpoint::url() ); ?></code></p>
			</td></tr>
			<?php foreach ( Sanitizer::EDITABLE_DIRECTIVES as $directive ) : ?>
				<tr><th scope="row"><label for="wpsh-csp-<?php echo esc_attr( $directive ); ?>"><code><?php echo esc_html( $directive ); ?></code></label></th><td>
					<input type="text" class="large-text code" id="wpsh-csp-<?php echo esc_attr( $directive ); ?>" name="<?php echo esc_attr( self::name( 'csp_directives', '[' . $directive . ']' ) ); ?>" value="<?php echo esc_attr( implode( ' ', (array) ( $s['csp_directives'][ $directive ] ?? array() ) ) ); ?>">
				</td></tr>
			<?php endforeach; ?>
			<tr><th scope="row"><?php echo esc_html__( 'Reports', 'wp-security-headers' ); ?></th><td>
				<label><?php echo esc_html__( 'Keep at most', 'wp-security-headers' ); ?> <input type="number" class="small-text" min="50" max="20000" name="<?php echo esc_attr( self::name( 'report_cap' ) ); ?>" value="<?php echo esc_attr( (string) (int) $s['report_cap'] ); ?>"> <?php echo esc_html__( 'distinct violations', 'wp-security-headers' ); ?></label><br>
				<label><?php echo esc_html__( 'Accept at most', 'wp-security-headers' ); ?> <input type="number" class="small-text" min="1" max="600" name="<?php echo esc_attr( self::name( 'report_rate_limit' ) ); ?>" value="<?php echo esc_attr( (string) (int) $s['report_rate_limit'] ); ?>"> <?php echo esc_html__( 'reports per minute from one visitor', 'wp-security-headers' ); ?></label>
			</td></tr>
			<tr><th scope="row"><?php echo esc_html__( 'Preview', 'wp-security-headers' ); ?></th><td>
				<div class="wpsh-preview"><code><?php echo esc_html( $policy->serialize() ); ?></code></div>
				<p class="description"><?php echo esc_html__( 'Leave a field empty to fall back to default-src. Keywords such as self are quoted for you; invalid sources are dropped when you save.', 'wp-security-headers' ); ?></p>
				<?php self::warnings_list( $policy->warnings() ); ?>
			</td></tr>
		</table>
		<?php
	}
}
