<?php

namespace Ayesh\StatelessCSRF;

final class StatelessCSRF {
  const HASH_ALGO = 'sha256';

  private $key;

  private $data = [];
  private $ttl = 0;

  private $provided_token;
  private $provided_data = [];

  public function __construct(string $secret_key, int $ttl = null) {
    $this->key = $secret_key;
    if ($ttl) {
      $this->setExpiration($ttl);
    }
  }

  private function urlSafeBase64Encode(string $input): string {
    $encoded = strtr(base64_encode($input), '+/', '-_');
    return rtrim($encoded, '=');
  }

  private function urlSafeBase64Decode(string $input): string {
    return base64_decode(strtr($input, '-_', '+/'));
  }

  public function setExpiration(int $ttl_seconds = 0) {
    if ($ttl_seconds < 0) {
      throw new \InvalidArgumentException('TTL should be negative.');
    }
    $this->ttl = $ttl_seconds;
    return $this;
  }

  public function addData(string $data, string $key = null) {
    if (null === $key) {
      $this->data[] = $data;
    }
    else {
      $this->data[$key] = $data;
    }

    return $this;
  }

  public function resetData() {
    $this->data = [];
  }

  private function generateKey(array $data = [], int $expiration): string {
    $output = [];
    $output[] = json_encode($data);

    if ($expiration) {
      $output[] = $expiration;
    }

    if (empty($expiration) && empty($data)) {
      throw new \BadMethodCallException('Attempting to generate key without setting data.');
    }

    return implode('|', $output);
  }

  private function generateHash(string $input): string {
    return hash_hmac(self::HASH_ALGO, $input, $this->key, false);
  }

  public function getToken(): string {
    $expiration = $this->ttl ? time() + $this->ttl : 0;
    $data = $this->generateKey($this->data, $expiration);
    $hash = $this->generateHash($data);
    return $this->urlSafeBase64Encode($data . '|' . $hash);
  }

  public function setToken(string $token) {
    $this->provided_token = $token;
    return $this;
  }

  private function decodeKey(string $provided_key) {
    $this->provided_data = [];
    $data = $this->urlSafeBase64Decode($provided_key);
    $data = explode('|', $data);
    if (count($data) < 2) {
      return false;
    }
    $return = [];
    $return['hash'] = array_pop($data);
    $return['expire'] = 0;
    if (count($data) > 1) {
      $return['expire'] = array_pop($data);
    }
    $return['data'] = json_decode($data[0], true);

    // @codeCoverageIgnoreStart
    if (!is_array($return['data']) || json_last_error()) {
      return false;
    }
    // @codeCoverageIgnoreEnd

    $this->provided_data = $return['data'];
    return $return;
  }

  public function validate(): bool {
    if (!$this->provided_token) {
      throw new \BadMethodCallException('Attempting to validate without setting the key and token.');
    }

    $data = $this->decodeKey($this->provided_token);
    if ($data === false) {
      return false;
    }
    if ($data['expire'] && time() > $data['expire']) {
      return false;
    }

    $key = $this->generateKey($data['data'], $data['expire']);
    $hash = $this->generateHash($key);
    return hash_equals($hash, $data['hash']);
  }

  public function getData(): array {
    return $this->provided_data;
  }
}
