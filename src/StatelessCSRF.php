<?php


namespace Ayesh\StatelessCSRF;


final class StatelessCSRF {
  private $key;

  public function __construct(string $secret_key) {
    $this->key = $secret_key;
  }

  public function generate(): string {

  }

  public function validate(string $token) {

  }
}
