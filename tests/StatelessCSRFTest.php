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

    $token = $csrf->getToken();

    $validator = new StatelessCSRF($secret);
    $validator->setToken($token);

    $is_valid = $validator->validate();
    $this->assertTrue($is_valid);
    $this->assertSame($random_data, $validator->getData());
  }

  /**
   * @dataProvider getRandomDataArray
   * @param array $random_data
   */
  public function testCorrectCSRFWithTTL(array $random_data) {
    $secret = $this->getRandomToken();
    $csrf = new StatelessCSRF($secret);
    $csrf->setExpiration(3600);

    foreach ($random_data as $index => $datum) {
      $csrf->addData($datum, $index);
    }

    $token = $csrf->getToken();

    $validator = new StatelessCSRF($secret);
    $validator->setToken($token);

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

    $token = $csrf->getToken();

    $validator = new StatelessCSRF($secret);
    $validator->setToken($token);

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

    $token = $csrf->getToken();

    $new_secret = $this->getRandomToken();
    $validator = new StatelessCSRF($new_secret);
    $validator->setToken($token);

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

    $validator->setToken($token);
    $this->assertTrue($validator->validate());

    $key = $this->getRandomToken();
    $validator->setToken($key);
    $this->assertFalse($validator->validate());

    $key = new \stdClass();
    $key->foo = $this->getRandomToken();
    $key = base64_encode(json_encode($key));
    $validator->setToken($key);
    $this->assertFalse($validator->validate());

    $key = true;
    $key = base64_encode(json_encode($key));
    $validator->setToken($key);
    $this->assertFalse($validator->validate());

    $token = implode('|', [
      true,
      500,
      $this->getRandomToken(),
    ]);
    $token = base64_encode($token);
    $validator->setToken($key);
    $this->assertFalse($validator->validate());
  }

  public function testExpiredToken() {
    $secret = $this->getRandomToken();

    $csrf = new StatelessCSRF($secret);
    $csrf->setExpiration(1);

    $csrf2 = new StatelessCSRF($secret, 1);
    $csrf2->addData('Ayesh');

    $token  =  $csrf->getToken();
    $token2 = $csrf2->getToken();

    sleep(2);

    $csrf ->setToken($token);
    $csrf2->setToken($token2);

    $this->assertFalse($csrf->validate());
    $this->assertFalse($csrf2->validate());
  }

  public function testNegativeTTLRejected() {
    $secret = $this->getRandomToken();
    $csrf = new StatelessCSRF($secret);

    $this->expectException(\InvalidArgumentException::class);
    $this->expectExceptionMessage('TTL should be negative.');

    $csrf->setExpiration(-5);
  }



  public function testContiniousCSRFGeneration() {
    $secret = $this->getRandomToken();
    $csrf = new StatelessCSRF($secret);

    $random_token = $this->getRandomToken();
    $csrf->addData($random_token);
    $token = $csrf->getToken();

    $this->assertTrue($csrf->setToken($token)->validate());
    $this->assertSame([$random_token], $csrf->getData());

    $csrf->resetData();
    $random_token = $this->getRandomToken();
    $random_token_val = $this->getRandomToken();
    $csrf->addData($random_token_val, $random_token);
    $token = $csrf->getToken();
    $this->assertTrue($csrf->setToken($token)->validate());
    $this->assertSame([$random_token => $random_token_val], $csrf->getData());
  }

  public function testDataTTLMissingException() {
    $secret = $this->getRandomToken();
    $csrf = new StatelessCSRF($secret);

    $this->expectException(\BadMethodCallException::class);
    $csrf->getToken();
  }
}
