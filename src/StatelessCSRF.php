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

  private function decodeKey(string $provided_key) {
    $data = base64_decode($provided_key);
    $data = json_decode($data, true);

    if (!is_array($data) || json_last_error()) {
      return false;
    }
    return $data;
  }

  public function validate(): bool {
    if (!$this->provided_token || !$this->provided_key) {
      throw new \BadMethodCallException('Attempting to validate without setting the key and token.');
    }

    $data = $this->decodeKey($this->provided_key);
    if ($data === false) {
      return false;
    }

    $this->data = $data;
    $token = $this->hmac();

    return hash_equals($this->provided_token, $token);
  }

  public function getData(): array {
    return $this->data;
  }
}
