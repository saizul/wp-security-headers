<?php
/**
 * Custom table for violation reports.
 *
 * @package Saizul\SecurityHeaders
 */

namespace Saizul\SecurityHeaders\Reports;

defined( 'ABSPATH' ) || exit;

/**
 * Stores deduplicated violations in `{prefix}security_headers_reports`.
 *
 * Each distinct violation (directive, blocked URI, source file, line,
 * disposition) is one row with a hit counter. The table is capped: when it
 * holds more rows than the cap, the least recently seen rows are deleted.
 * No IP addresses or user agents are stored.
 */
final class Store implements ReportStore {

	const DB_VERSION        = '1';
	const DB_VERSION_OPTION = 'wp_security_headers_db_version';
	const TABLE             = 'security_headers_reports';

	/**
	 * Database.
	 *
	 * @var \wpdb
	 */
	private $db;

	/**
	 * Constructor.
	 *
	 * @param \wpdb|object|null $db Database, global $wpdb by default.
	 */
	public function __construct( $db = null ) {
		if ( null === $db ) {
			global $wpdb;
			$db = $wpdb;
		}
		$this->db = $db;
	}

	/**
	 * Full table name.
	 */
	public function table(): string {
		return $this->db->prefix . self::TABLE;
	}

	/**
	 * Create or update the table.
	 */
	public function install(): void {
		if ( ! function_exists( 'dbDelta' ) ) {
			require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		}
		$table   = $this->table();
		$collate = $this->db->get_charset_collate();
		$sql     = "CREATE TABLE {$table} (
  id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  hash char(40) NOT NULL,
  directive varchar(40) NOT NULL DEFAULT '',
  blocked_uri varchar(512) NOT NULL DEFAULT '',
  document_uri varchar(512) NOT NULL DEFAULT '',
  source_file varchar(512) NOT NULL DEFAULT '',
  line_number int(10) unsigned NOT NULL DEFAULT 0,
  sample varchar(256) NOT NULL DEFAULT '',
  disposition varchar(16) NOT NULL DEFAULT '',
  hits int(10) unsigned NOT NULL DEFAULT 1,
  first_seen datetime NOT NULL,
  last_seen datetime NOT NULL,
  PRIMARY KEY  (id),
  UNIQUE KEY hash (hash),
  KEY last_seen (last_seen)
) {$collate};";

		dbDelta( $sql );
		update_option( self::DB_VERSION_OPTION, self::DB_VERSION );
	}

	/**
	 * Install when the table is missing or outdated on this site.
	 */
	public function maybe_install(): void {
		if ( self::DB_VERSION !== get_option( self::DB_VERSION_OPTION, '' ) ) {
			$this->install();
		}
	}

	/**
	 * Drop the table (uninstall).
	 */
	public function drop(): void {
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange -- Removing the plugin's own table.
		$this->db->query( $this->db->prepare( 'DROP TABLE IF EXISTS %i', $this->table() ) );
		delete_option( self::DB_VERSION_OPTION );
	}

	/**
	 * Hash that identifies a distinct violation.
	 *
	 * @param array<string,mixed> $v Violation.
	 */
	public static function hash( array $v ): string {
		return sha1( implode( "\n", array( $v['directive'], $v['blocked_uri'], $v['source_file'], (string) $v['line'], $v['disposition'] ) ) );
	}

	/**
	 * {@inheritDoc}
	 *
	 * @param array<string,mixed> $violation Violation.
	 * @param int                 $now       Current time.
	 * @param int                 $cap       Most rows to keep.
	 */
	public function record( array $violation, int $now, int $cap ): void {
		$time = gmdate( 'Y-m-d H:i:s', $now );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Write to the plugin's own table.
		$result = $this->db->query(
			$this->db->prepare(
				'INSERT INTO %i (hash, directive, blocked_uri, document_uri, source_file, line_number, sample, disposition, hits, first_seen, last_seen) VALUES (%s, %s, %s, %s, %s, %d, %s, %s, 1, %s, %s) ON DUPLICATE KEY UPDATE hits = hits + 1, last_seen = VALUES(last_seen), document_uri = VALUES(document_uri), sample = VALUES(sample)',
				$this->table(),
				self::hash( $violation ),
				(string) $violation['directive'],
				(string) $violation['blocked_uri'],
				(string) $violation['document'],
				(string) $violation['source_file'],
				(int) $violation['line'],
				(string) $violation['sample'],
				(string) $violation['disposition'],
				$time,
				$time
			)
		);

		// MySQL reports 1 affected row for an insert and 2 for an update.
		if ( 1 === $result ) {
			$this->enforce_cap( $cap );
		}
	}

	/**
	 * Delete the least recently seen rows above the cap.
	 *
	 * @param int $cap Most rows to keep.
	 */
	public function enforce_cap( int $cap ): void {
		$excess = $this->count() - max( 1, $cap );
		if ( $excess <= 0 ) {
			return;
		}
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Prune the plugin's own table.
		$this->db->query( $this->db->prepare( 'DELETE FROM %i ORDER BY last_seen ASC, id ASC LIMIT %d', $this->table(), $excess ) );
	}

	/**
	 * {@inheritDoc}
	 */
	public function count(): int {
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Live count of the plugin's own table.
		return (int) $this->db->get_var( $this->db->prepare( 'SELECT COUNT(*) FROM %i', $this->table() ) );
	}

	/**
	 * {@inheritDoc}
	 *
	 * @param int $limit  Rows.
	 * @param int $offset Offset.
	 * @return array<int,array<string,mixed>>
	 */
	public function rows( int $limit, int $offset = 0 ): array {
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Read the plugin's own table.
		$rows = $this->db->get_results(
			$this->db->prepare(
				'SELECT directive, blocked_uri, document_uri, source_file, line_number, sample, disposition, hits, first_seen, last_seen FROM %i ORDER BY hits DESC, last_seen DESC LIMIT %d OFFSET %d',
				$this->table(),
				max( 1, $limit ),
				max( 0, $offset )
			),
			ARRAY_A
		);

		return is_array( $rows ) ? $rows : array();
	}

	/**
	 * {@inheritDoc}
	 */
	public function clear(): void {
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Empty the plugin's own table.
		$this->db->query( $this->db->prepare( 'DELETE FROM %i', $this->table() ) );
	}
}
