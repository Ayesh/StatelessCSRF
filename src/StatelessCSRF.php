<?php

namespace Ayesh\StatelessCSRF;

final class StatelessCSRF {
  const HASH_ALGO = 'sha256';

  private $key;
  private $data = [];
  private $provided_token;
  private $provided_key;

  public function __construct(string $secret_key) {
    $this->key = $secret_key;
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

  public function getKey(): string {
    return base64_encode(json_encode($this->data));
  }

  public function getToken(): string {
    return $this->hmac();
  }

  private function hmac(): string {
    return hash_hmac(self::HASH_ALGO, $this->getKey(), $this->key, false);
  }

  public function setKey(string $key) {
    $this->provided_key = $key;
    return $this;
  }

  public function setToken(string $token) {
    $this->provided_token = $token;
  }

  public function validate(): bool {
    if (!$this->provided_token || !$this->provided_key) {
      throw new \BadMethodCallException('Attempting to validate without setting the key and token.');
    }

    $data = base64_decode($this->provided_key);
    $data = json_decode($data, true);
    if (json_last_error()) {
      return false;
    }

    if (!is_array($data)) {
      return false;
    }

    foreach ($this->data as $key => $datum) {
      if (!is_string($datum)) {
        return false;
      }
    }

    $this->data = $data;
    $token = $this->hmac();

    return hash_equals($this->provided_token, $token);
  }

  public function getData(): array {
    return $this->data;
  }
}
