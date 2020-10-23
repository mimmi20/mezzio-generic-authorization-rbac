<?php
/**
 * This file is part of the mimmi20/mezzio-generic-authorization-rbac package.
 *
 * Copyright (c) 2020, Thomas Mueller <mimmi20@live.de>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

declare(strict_types = 1);
namespace MezzioTest\GenericAuthorization\Rbac;

use Mezzio\GenericAuthorization\Exception;
use Mezzio\GenericAuthorization\Rbac\LaminasRbac;
use Mezzio\GenericAuthorization\Rbac\LaminasRbacAssertionInterface;
use Mezzio\GenericAuthorization\Rbac\LaminasRbacFactory;
use PHPUnit\Framework\TestCase;
use Prophecy\Prophecy\ObjectProphecy;
use Psr\Container\ContainerInterface;

final class LaminasRbacFactoryTest extends TestCase
{
    /** @var ContainerInterface|ObjectProphecy */
    private $container;

    /**
     * @return void
     */
    protected function setUp(): void
    {
        $this->container = $this->prophesize(ContainerInterface::class);
    }

    /**
     * @return void
     */
    public function testFactoryWithoutConfig(): void
    {
        $this->container->get('config')->willReturn([]);

        $factory = new LaminasRbacFactory();

        $this->expectException(Exception\InvalidConfigException::class);
        $this->expectExceptionMessage('mezzio-authorization-rbac');
        $factory($this->container->reveal());
    }

    /**
     * @return void
     */
    public function testFactoryWithoutLaminasRbacConfig(): void
    {
        $this->container->get('config')->willReturn(['mezzio-authorization-rbac' => []]);

        $factory = new LaminasRbacFactory();

        $this->expectException(Exception\InvalidConfigException::class);
        $this->expectExceptionMessage('mezzio-authorization-rbac.roles');
        $factory($this->container->reveal());
    }

    /**
     * @return void
     */
    public function testFactoryWithoutPermissions(): void
    {
        $this->container->get('config')->willReturn([
            'mezzio-authorization-rbac' => [
                'roles' => [],
            ],
        ]);

        $factory = new LaminasRbacFactory();

        $this->expectException(Exception\InvalidConfigException::class);
        $this->expectExceptionMessage('mezzio-authorization-rbac.permissions');
        $factory($this->container->reveal());
    }

    /**
     * @return void
     */
    public function testFactoryWithEmptyRolesPermissionsWithoutAssertion(): void
    {
        $this->container->get('config')->willReturn([
            'mezzio-authorization-rbac' => [
                'roles' => [],
                'permissions' => [],
            ],
        ]);
        $this->container->has(LaminasRbacAssertionInterface::class)->willReturn(false);
        $this->container->has(\Zend\Expressive\Authorization\Rbac\ZendRbacAssertionInterface::class)->willReturn(false);

        $factory     = new LaminasRbacFactory();
        $laminasRbac = $factory($this->container->reveal());
        self::assertInstanceOf(LaminasRbac::class, $laminasRbac);
    }

    /**
     * @return void
     */
    public function testFactoryWithEmptyRolesPermissionsWithAssertion(): void
    {
        $this->container->get('config')->willReturn([
            'mezzio-authorization-rbac' => [
                'roles' => [],
                'permissions' => [],
            ],
        ]);

        $assertion = $this->prophesize(LaminasRbacAssertionInterface::class);
        $this->container->has(LaminasRbacAssertionInterface::class)->willReturn(true);
        $this->container->get(LaminasRbacAssertionInterface::class)->willReturn($assertion->reveal());

        $factory     = new LaminasRbacFactory();
        $laminasRbac = $factory($this->container->reveal());
        self::assertInstanceOf(LaminasRbac::class, $laminasRbac);
    }

    /**
     * @return void
     */
    public function testFactoryWithoutAssertion(): void
    {
        $this->container->get('config')->willReturn([
            'mezzio-authorization-rbac' => [
                'roles' => [
                    'administrator' => [],
                    'editor' => ['administrator'],
                    'contributor' => ['editor'],
                ],
                'permissions' => [
                    'contributor' => [
                        'admin.dashboard',
                        'admin.posts',
                    ],
                    'editor' => ['admin.publish'],
                    'administrator' => ['admin.settings'],
                ],
            ],
        ]);
        $this->container->has(LaminasRbacAssertionInterface::class)->willReturn(false);
        $this->container->has(\Zend\Expressive\Authorization\Rbac\ZendRbacAssertionInterface::class)->willReturn(false);

        $factory     = new LaminasRbacFactory();
        $laminasRbac = $factory($this->container->reveal());
        self::assertInstanceOf(LaminasRbac::class, $laminasRbac);
    }

    /**
     * @return void
     */
    public function testFactoryWithAssertion(): void
    {
        $this->container->get('config')->willReturn([
            'mezzio-authorization-rbac' => [
                'roles' => [
                    'administrator' => [],
                    'editor' => ['administrator'],
                    'contributor' => ['editor'],
                ],
                'permissions' => [
                    'contributor' => [
                        'admin.dashboard',
                        'admin.posts',
                    ],
                    'editor' => ['admin.publish'],
                    'administrator' => ['admin.settings'],
                ],
            ],
        ]);
        $assertion = $this->prophesize(LaminasRbacAssertionInterface::class);
        $this->container->has(LaminasRbacAssertionInterface::class)->willReturn(true);
        $this->container->get(LaminasRbacAssertionInterface::class)->willReturn($assertion->reveal());

        $factory     = new LaminasRbacFactory();
        $laminasRbac = $factory($this->container->reveal());
        self::assertInstanceOf(LaminasRbac::class, $laminasRbac);
    }

    /**
     * @return void
     */
    public function testFactoryWithInvalidRole(): void
    {
        $this->container->get('config')->willReturn([
            'mezzio-authorization-rbac' => [
                'roles' => [
                    1 => [],
                ],
                'permissions' => [],
            ],
        ]);
        $this->container->has(LaminasRbacAssertionInterface::class)->willReturn(false);
        $this->container->has(\Zend\Expressive\Authorization\Rbac\ZendRbacAssertionInterface::class)->willReturn(false);

        $factory = new LaminasRbacFactory();

        $this->expectException(Exception\InvalidConfigException::class);
        $factory($this->container->reveal());
    }

    /**
     * @return void
     */
    public function testFactoryWithUnknownRole(): void
    {
        $this->container->get('config')->willReturn([
            'mezzio-authorization-rbac' => [
                'roles' => [
                    'administrator' => [],
                ],
                'permissions' => [
                    'contributor' => [
                        'admin.dashboard',
                        'admin.posts',
                    ],
                ],
            ],
        ]);
        $this->container->has(LaminasRbacAssertionInterface::class)->willReturn(false);
        $this->container->has(\Zend\Expressive\Authorization\Rbac\ZendRbacAssertionInterface::class)->willReturn(false);

        $factory = new LaminasRbacFactory();

        $this->expectException(Exception\InvalidConfigException::class);
        $factory($this->container->reveal());
    }
}
