<?php
/**
 * Removes the plugin's data when it is deleted from the Plugins screen.
 *
 * Deletes the settings, the last scan, the database version option and the
 * violation reports table on every site of a network.
 *
 * @package Saizul\SecurityHeaders
 */

defined( 'WP_UNINSTALL_PLUGIN' ) || exit;

/**
 * Delete the data of the current site.
 */
function wp_security_headers_uninstall_site() {
	global $wpdb;

	delete_option( 'wp_security_headers_settings' );
	delete_option( 'wp_security_headers_last_scan' );
	delete_option( 'wp_security_headers_db_version' );

	// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange -- Removing the plugin's own table.
	$wpdb->query( $wpdb->prepare( 'DROP TABLE IF EXISTS %i', $wpdb->prefix . 'security_headers_reports' ) );
}

if ( is_multisite() ) {
	$wp_security_headers_site_ids = get_sites(
		array(
			'fields' => 'ids',
			'number' => 0,
		)
	);
	foreach ( $wp_security_headers_site_ids as $wp_security_headers_site_id ) {
		switch_to_blog( (int) $wp_security_headers_site_id );
		wp_security_headers_uninstall_site();
		restore_current_blog();
	}
} else {
	wp_security_headers_uninstall_site();
}
