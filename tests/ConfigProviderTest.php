<?php

/**
 * This file is part of the mimmi20/mezzio-generic-authorization-rbac package.
 *
 * Copyright (c) 2020-2025, Thomas Mueller <mimmi20@live.de>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

declare(strict_types = 1);

namespace Mimmi20\Mezzio\GenericAuthorization\Rbac;

use Mimmi20\Mezzio\GenericAuthorization\AuthorizationInterface;
use PHPUnit\Framework\Exception;
use PHPUnit\Framework\TestCase;

final class ConfigProviderTest extends TestCase
{
    /** @throws Exception */
    public function testReturnedArrayContainsDependencies(): void
    {
        $config = (new ConfigProvider())();
        self::assertIsArray($config);

        self::assertArrayHasKey('dependencies', $config);

        $dependencies = $config['dependencies'];
        self::assertIsArray($dependencies);
        self::assertArrayHasKey('factories', $dependencies);
        self::assertArrayHasKey('aliases', $dependencies);

        $factories = $dependencies['factories'];
        self::assertIsArray($factories);
        self::assertArrayHasKey(LaminasRbac::class, $factories);

        $aliases = $dependencies['aliases'];
        self::assertIsArray($aliases);
        self::assertArrayHasKey(AuthorizationInterface::class, $aliases);
    }

    /** @throws Exception */
    public function testGetDependenciesReturnedArrayContainsDependencies(): void
    {
        $dependencies = (new ConfigProvider())->getDependencies();
        self::assertIsArray($dependencies);
        self::assertArrayHasKey('factories', $dependencies);
        self::assertArrayHasKey('aliases', $dependencies);

        $factories = $dependencies['factories'];
        self::assertIsArray($factories);
        self::assertArrayHasKey(LaminasRbac::class, $factories);

        $aliases = $dependencies['aliases'];
        self::assertIsArray($aliases);
        self::assertArrayHasKey(AuthorizationInterface::class, $aliases);
    }
}
