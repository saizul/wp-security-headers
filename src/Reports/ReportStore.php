<?php
/**
 * Storage contract for violation reports.
 *
 * @package Saizul\SecurityHeaders
 */

namespace Saizul\SecurityHeaders\Reports;

defined( 'ABSPATH' ) || exit;

/**
 * Where violation reports are kept.
 */
interface ReportStore {

	/**
	 * Record one normalised violation (see Parser::normalize()). Repeated
	 * violations increase a hit counter instead of adding rows.
	 *
	 * @param array<string,mixed> $violation Violation.
	 * @param int                 $now       Current time.
	 * @param int                 $cap       Most rows to keep.
	 */
	public function record( array $violation, int $now, int $cap ): void;

	/**
	 * Number of distinct violations stored.
	 */
	public function count(): int;

	/**
	 * Stored violations, most frequent first.
	 *
	 * @param int $limit  Rows.
	 * @param int $offset Offset.
	 * @return array<int,array<string,mixed>>
	 */
	public function rows( int $limit, int $offset = 0 ): array;

	/**
	 * Delete every stored violation.
	 */
	public function clear(): void;
}
