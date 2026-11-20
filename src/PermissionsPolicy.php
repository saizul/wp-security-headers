<?php
/**
 * Permissions-Policy features and serialisation.
 *
 * @package Saizul\SecurityHeaders
 */

namespace Saizul\SecurityHeaders;

defined( 'ABSPATH' ) || exit;

/**
 * Builds the Permissions-Policy header from feature => allowlist choices.
 */
final class PermissionsPolicy {

	const NONE = 'none';
	const SELF = 'self';

	/**
	 * Features offered in the builder, with a short explanation.
	 *
	 * @return array<string,string>
	 */
	public static function features(): array {
		return array(
			'accelerometer'                  => __( 'Motion sensors (accelerometer). Some video embeds ask for it.', 'wp-security-headers' ),
			'autoplay'                       => __( 'Autoplay of media with sound.', 'wp-security-headers' ),
			'bluetooth'                      => __( 'Web Bluetooth.', 'wp-security-headers' ),
			'browsing-topics'                => __( 'Topics API (interest-based advertising).', 'wp-security-headers' ),
			'camera'                         => __( 'Camera.', 'wp-security-headers' ),
			'display-capture'                => __( 'Screen capture.', 'wp-security-headers' ),
			'encrypted-media'                => __( 'Encrypted media (DRM video).', 'wp-security-headers' ),
			'fullscreen'                     => __( 'Fullscreen. Video embeds need it.', 'wp-security-headers' ),
			'geolocation'                    => __( 'Location. Store locators and maps may need it.', 'wp-security-headers' ),
			'gyroscope'                      => __( 'Motion sensors (gyroscope).', 'wp-security-headers' ),
			'hid'                            => __( 'WebHID devices.', 'wp-security-headers' ),
			'idle-detection'                 => __( 'Idle detection.', 'wp-security-headers' ),
			'magnetometer'                   => __( 'Magnetometer.', 'wp-security-headers' ),
			'microphone'                     => __( 'Microphone.', 'wp-security-headers' ),
			'midi'                           => __( 'Web MIDI.', 'wp-security-headers' ),
			'payment'                        => __( 'Payment Request API. Apple Pay and Google Pay buttons need it.', 'wp-security-headers' ),
			'picture-in-picture'             => __( 'Picture-in-picture video.', 'wp-security-headers' ),
			'publickey-credentials-get'      => __( 'Passkeys and security keys (WebAuthn) in frames.', 'wp-security-headers' ),
			'screen-wake-lock'               => __( 'Keep the screen awake.', 'wp-security-headers' ),
			'serial'                         => __( 'Web Serial.', 'wp-security-headers' ),
			'usb'                            => __( 'WebUSB.', 'wp-security-headers' ),
			'web-share'                      => __( 'Web Share.', 'wp-security-headers' ),
			'xr-spatial-tracking'            => __( 'VR and AR (WebXR).', 'wp-security-headers' ),
			'otp-credentials'                => __( 'One-time codes from SMS (WebOTP).', 'wp-security-headers' ),
			'identity-credentials-get'       => __( 'Federated sign-in (FedCM).', 'wp-security-headers' ),
			'attribution-reporting'          => __( 'Attribution Reporting API (ad conversion measurement).', 'wp-security-headers' ),
			'private-state-token-issuance'   => __( 'Private State Tokens: issuing.', 'wp-security-headers' ),
			'private-state-token-redemption' => __( 'Private State Tokens: redeeming.', 'wp-security-headers' ),
		);
	}

	/**
	 * Safe defaults: features most sites never use are switched off.
	 *
	 * @return array<string,string>
	 */
	public static function defaults(): array {
		return array(
			'browsing-topics' => self::NONE,
			'camera'          => self::NONE,
			'display-capture' => self::NONE,
			'geolocation'     => self::NONE,
			'hid'             => self::NONE,
			'microphone'      => self::NONE,
			'midi'            => self::NONE,
			'serial'          => self::NONE,
			'usb'             => self::NONE,
		);
	}

	/**
	 * Keep known features with a valid allowlist, in the builder's order.
	 *
	 * @param mixed $input Feature => 'none'|'self'.
	 * @return array<string,string>
	 */
	public static function sanitize( $input ): array {
		if ( ! is_array( $input ) ) {
			return array();
		}
		$out = array();
		foreach ( array_keys( self::features() ) as $feature ) {
			if ( isset( $input[ $feature ] ) && in_array( $input[ $feature ], array( self::NONE, self::SELF ), true ) ) {
				$out[ $feature ] = $input[ $feature ];
			}
		}

		return $out;
	}

	/**
	 * Header value, for example `camera=(), fullscreen=(self)`.
	 *
	 * @param array<string,string> $map Feature => allowlist.
	 */
	public static function serialize( array $map ): string {
		$parts = array();
		foreach ( self::sanitize( $map ) as $feature => $allow ) {
			$parts[] = $feature . '=' . ( self::SELF === $allow ? '(self)' : '()' );
		}

		return implode( ', ', $parts );
	}
}
