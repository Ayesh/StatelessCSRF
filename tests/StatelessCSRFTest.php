<?php

namespace Ayesh\StatelessCSRF\Tests;

use Ayesh\StatelessCSRF\StatelessCSRF;
use PHPUnit\Framework\TestCase;

class StatelessCSRFTest extends TestCase {
  public function getRandomDataArray(): array {
    $data = [];
    for ($i = 1; $i <= 5; $i++) {
      $data[$i] = bin2hex(random_bytes(8));
    }
    return [[$data]];
  }

  protected function getRandomToken(): string {
    return base64_encode(random_bytes(16));
  }

  /**
   * @dataProvider getRandomDataArray
   * @param array $random_data
   */
  public function testCorrectCSRF(array $random_data) {
    $secret = $this->getRandomToken();
    $csrf = new StatelessCSRF($secret);

    foreach ($random_data as $index => $datum) {
      $csrf->addData($datum, $index);
    }

    $key = $csrf->getKey();
    $token = $csrf->getToken();


    $validator = new StatelessCSRF($secret);
    $validator->setKey($key)->setToken($token);

    $is_valid = $validator->validate();
    $this->assertTrue($is_valid);
    $this->assertSame($random_data, $validator->getData());
  }

  /**
   * @dataProvider getRandomDataArray
   * @param array $random_data
   */
  public function testCorrectCSRFWithAutoIndex(array $random_data) {
    $secret = $this->getRandomToken();
    $csrf = new StatelessCSRF($secret);

    $random_data = array_values($random_data);
    foreach ($random_data as $datum) {
      $csrf->addData($datum);
    }

    $key = $csrf->getKey();
    $token = $csrf->getToken();


    $validator = new StatelessCSRF($secret);
    $validator->setKey($key)->setToken($token);

    $is_valid = $validator->validate();
    $this->assertTrue($is_valid);
    $this->assertSame($random_data, $validator->getData());
  }

  /**
   * @dataProvider getRandomDataArray
   * @param array $random_data
   */
  public function testIncorrectSecretKey(array $random_data) {
    $secret = $this->getRandomToken();
    $csrf = new StatelessCSRF($secret);

    foreach ($random_data as $index => $datum) {
      $csrf->addData($datum, $index);
    }

    $key = $csrf->getKey();
    $token = $csrf->getToken();

    $new_secret = $this->getRandomToken();
    $validator = new StatelessCSRF($new_secret);
    $validator->setKey($key)->setToken($token);

    $is_valid = $validator->validate();
    $this->assertFalse($is_valid);
  }

  public function testRejectValidationWithoutToken() {
    $secret = $this->getRandomToken();
    $validator = new StatelessCSRF($secret);

    $this->expectException(\BadMethodCallException::class);
    $validator->validate();
  }

  public function testRejectInvalidJsonData() {
    $secret = $this->getRandomToken();
    $validator = new StatelessCSRF($secret);

    $data = $this->getRandomToken();
    $validator->addData($data);
    $token = $validator->getToken();
    $key = $validator->getKey();

    $validator->setToken($token);
    $validator->setKey($key);
    $this->assertTrue($validator->validate());

    $key = $this->getRandomToken();
    $validator->setKey($key);
    $this->assertFalse($validator->validate());

    $key = new \stdClass();
    $key->foo = $this->getRandomToken();
    $key = base64_encode(json_encode($key));
    $validator->setKey($key);
    $this->assertFalse($validator->validate());

    $key = true;
    $key = base64_encode(json_encode($key));
    $validator->setKey($key);
    $this->assertFalse($validator->validate());
  }
}
