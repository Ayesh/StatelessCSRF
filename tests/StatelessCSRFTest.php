<?php

namespace Ayesh\StatelessCSRF\Tests;

use Ayesh\StatelessCSRF\StatelessCSRF;
use PHPUnit\Framework\TestCase;

class StatelessCSRFTest extends TestCase {

	public function testInit(): void {
		$instance = new StatelessCSRF('test');
		$this->assertInstanceOf(StatelessCSRF::class, $instance);
	}

	public function testStatelessNoGlue(): void {
		$key       = bin2hex(random_bytes(8));
		$generator = new StatelessCSRF($key);
		$validator = new StatelessCSRF($key);

		$id = bin2hex(random_bytes(8));
		$this->assertTrue($validator->validate($id, $generator->getToken($id)));
	}

	/**
	 * @dataProvider getValidationDataSet
	 *
	 * @param string $key
	 * @param string $value
	 * @param string $id
	 */
	public function testValidateToken(string $key, string $value, string $id): void {
		$instance = new StatelessCSRF('test');
		$instance->setGlueData($key, $value);
		$result = $instance->getToken($id);
		$this->assertStringNotContainsString('|', $result);

		$instance->validate($id, $result, time());
	}

	public function getValidationDataSet(): array {
		return [
			['foo', 'bar', 'id'],
			['foo', 'foo', 'foo'],
			['foo', 'foo|baz', 'id|baz'],
			['foo', 'foo||||baz', '||'],
			['||', '||', '||'],
		];
	}

	/**
	 * @dataProvider getValidationDataSet
	 *
	 * @param string $key
	 * @param string $value
	 * @param string $id
	 *
	 * @throws \Exception
	 */
	public function testSeparateInstanceValidation(string $key, string $value, string $id): void {
		$secret_key = bin2hex(random_bytes(8));

		$generator      = new StatelessCSRF($secret_key);
		$validator      = new StatelessCSRF($secret_key);
		$invalid_secret = new StatelessCSRF(str_rot13($secret_key));

		$generator->setGlueData($key, $value);
		$validator->setGlueData($key, $value);

		$token = $generator->getToken($id);

		$this->assertTrue($validator->validate($id, $token));
		$this->assertFalse($invalid_secret->validate($id, $token));
		$this->assertTrue($validator->validate($id, $token, time() - 1)); // Test tokens without expiration.
		$this->assertFalse($invalid_secret->validate($id, $token, time() - 1));

		$validator->resetGlue();
		$this->assertFalse($validator->validate($id, $token));
		$this->assertFalse($validator->validate($id, $token, time() - 1));

		$new_validator = new StatelessCSRF($secret_key);
		$new_validator->setGlueData($key, $value);
		$this->assertTrue($new_validator->validate($id, $token));
	}

	/**
	 * @dataProvider getValidationDataSet
	 *
	 * @param string $key
	 * @param string $value
	 * @param string $id
	 *
	 * @throws \Exception
	 */
	public function testTokenExpiration(string $key, string $value, string $id): void {
		$secret_key = bin2hex(random_bytes(8));

		$generator = new StatelessCSRF($secret_key);
		$validator = new StatelessCSRF($secret_key);

		$generator->setGlueData($key, $value);
		$validator->setGlueData($key, $value);

		$time  = time();
		$token = $generator->getToken($id, $time + 3600);

		$this->assertTrue($validator->validate($id, $token, $time));
		$this->assertTrue($validator->validate($id, $token, $time + 3600));
	}

	public function testDebugInfoLeakNoSecret(): void {
		$secret_key = bin2hex(random_bytes(8));
		$generator  = new StatelessCSRF($secret_key);
		$val        = print_r($generator, true);
		$this->assertStringNotContainsString($secret_key, $val);
	}
}
