<?php

namespace Ayesh\StatelessCSRF;

class StatelessCSRF {

    private const HASH_ALGO = 'sha256';

    private $key;

    private $data = [];

    public function __construct(string $secret_key) {
        $this->key = $secret_key;
    }

    /**
     * Set data that can be used to identify a user. IP address and User-Agent string
     * are ideal candidates.
     *
     * @param  string  $key
     * @param  string  $value
     */
    public function setGlueData(string $key, string $value): void {
        $this->data[$key] = $value;
    }

    public function resetGlue(): void {
        $this->data = [];
    }

    public function getToken(string $identifier, int $expiration = null): string {
        $seed = $this->getRandomSeed();
        $hash = $this->generateHash($identifier, $seed, $expiration, $this->data);
        return $this->urlSafeBase64Encode($seed . '|' . $expiration . '|' . $hash);
    }

    private function getRandomSeed(): string {
        return $this->urlSafeBase64Encode(random_bytes(8));
    }

    private function urlSafeBase64Encode(string $input): string {
        $encoded = strtr(base64_encode($input), '+/', '-_');
        return rtrim($encoded, '=');
    }

    private function generateHash(
      string $identifier,
      string $random_seed,
      int $expiration = null,
      array $data = []
    ): string {
        if (null === $expiration) {
            /** @noinspection CallableParameterUseCaseInTypeContextInspection */
            $expiration = '';
        }

        $identifier = $this->urlSafeBase64Encode($identifier);
        $props      = [$identifier, $expiration, json_encode($data, JSON_THROW_ON_ERROR, 512), $random_seed];

        return $this->urlSafeBase64Encode(hash_hmac(static::HASH_ALGO, implode('|', $props), $this->key, true));
    }

    public function validate(string $identifier, string $provided_token, int $current_time = null): bool {
        $provided_token = $this->urlSafeBase64Decode($provided_token);
        if (!$provided_token) {
            return false;
        }

        $parts = explode('|', $provided_token, 3);
        if (count($parts) !== 3) {
            return false;
        }

        if ($parts[1] === '') {
            $expiration = null;
        } elseif (!is_numeric($parts[1]) || $current_time > $parts[1]) {
            return false;
        } else {
            $expiration = (int)$parts[1];
        }

        $hash = $this->generateHash($identifier, $parts[0], $expiration, $this->data);
        return hash_equals($hash, $parts[2]);
    }

    private function urlSafeBase64Decode(string $input): string {
        return base64_decode(strtr($input, '-_', '+/'));
    }

    public function __debugInfo(): array {
        return [
          'data' => $this->data,
        ];
    }

}
