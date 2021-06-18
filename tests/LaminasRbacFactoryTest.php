<?php
/**
 * This file is part of the mimmi20/mezzio-generic-authorization-rbac package.
 *
 * Copyright (c) 2020-2021, Thomas Mueller <mimmi20@live.de>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

declare(strict_types = 1);

namespace MezzioTest\GenericAuthorization\Rbac;

use Laminas\Permissions\Rbac\Rbac;
use Laminas\Permissions\Rbac\RoleInterface;
use Laminas\ServiceManager\Exception\ServiceNotFoundException;
use Mezzio\GenericAuthorization\Exception;
use Mezzio\GenericAuthorization\Exception\RuntimeException;
use Mezzio\GenericAuthorization\Rbac\LaminasRbac;
use Mezzio\GenericAuthorization\Rbac\LaminasRbacAssertionInterface;
use Mezzio\GenericAuthorization\Rbac\LaminasRbacFactory;
use PHPUnit\Framework\TestCase;
use Psr\Container\ContainerInterface;
use ReflectionException;
use ReflectionProperty;
use SebastianBergmann\RecursionContext\InvalidArgumentException;

use function assert;

final class LaminasRbacFactoryTest extends TestCase
{
    /**
     * @throws \PHPUnit\Framework\Exception
     */
    public function testFactoryWithoutConfig(): void
    {
        $container = $this->getMockBuilder(ContainerInterface::class)
            ->disableOriginalConstructor()
            ->getMock();
        $container->expects(self::once())
            ->method('get')
            ->with('config')
            ->willReturn([]);
        $container->expects(self::never())
            ->method('has');

        $factory = new LaminasRbacFactory();

        $this->expectException(Exception\InvalidConfigException::class);
        $this->expectExceptionMessage('Cannot create Mezzio\GenericAuthorization\Rbac\LaminasRbac instance; no "mezzio-authorization-rbac" config key present');
        $this->expectExceptionCode(0);

        assert($container instanceof ContainerInterface);
        $factory($container);
    }

    /**
     * @throws \PHPUnit\Framework\Exception
     */
    public function testFactoryWithConfigException(): void
    {
        $container = $this->getMockBuilder(ContainerInterface::class)
            ->disableOriginalConstructor()
            ->getMock();
        $container->expects(self::once())
            ->method('get')
            ->with('config')
            ->willThrowException(new ServiceNotFoundException('test'));
        $container->expects(self::never())
            ->method('has');

        $factory = new LaminasRbacFactory();

        $this->expectException(Exception\InvalidConfigException::class);
        $this->expectExceptionMessage('Could not read mezzio-authorization-rbac config');
        $this->expectExceptionCode(0);

        assert($container instanceof ContainerInterface);
        $factory($container);
    }

    /**
     * @throws \PHPUnit\Framework\Exception
     */
    public function testFactoryWithoutLaminasRbacConfig(): void
    {
        $container = $this->getMockBuilder(ContainerInterface::class)
            ->disableOriginalConstructor()
            ->getMock();
        $container->expects(self::once())
            ->method('get')
            ->with('config')
            ->willReturn(['mezzio-authorization-rbac' => []]);
        $container->expects(self::never())
            ->method('has');

        $factory = new LaminasRbacFactory();

        $this->expectException(Exception\InvalidConfigException::class);
        $this->expectExceptionMessage('Cannot create Mezzio\GenericAuthorization\Rbac\LaminasRbac instance; no mezzio-authorization-rbac.roles configured');
        $this->expectExceptionCode(0);

        assert($container instanceof ContainerInterface);
        $factory($container);
    }

    /**
     * @throws \PHPUnit\Framework\Exception
     */
    public function testFactoryWithoutPermissions(): void
    {
        $container = $this->getMockBuilder(ContainerInterface::class)
            ->disableOriginalConstructor()
            ->getMock();
        $container->expects(self::once())
            ->method('get')
            ->with('config')
            ->willReturn(
                [
                    'mezzio-authorization-rbac' => [
                        'roles' => [],
                    ],
                ]
            );
        $container->expects(self::never())
            ->method('has');

        $factory = new LaminasRbacFactory();

        $this->expectException(Exception\InvalidConfigException::class);
        $this->expectExceptionMessage('Cannot create Mezzio\GenericAuthorization\Rbac\LaminasRbac instance; no mezzio-authorization-rbac.permissions configured');
        $this->expectExceptionCode(0);

        assert($container instanceof ContainerInterface);
        $factory($container);
    }

    /**
     * @throws \PHPUnit\Framework\Exception
     * @throws InvalidArgumentException
     */
    public function testFactoryWithEmptyRolesPermissionsWithoutAssertion(): void
    {
        $container = $this->getMockBuilder(ContainerInterface::class)
            ->disableOriginalConstructor()
            ->getMock();
        $container->expects(self::once())
            ->method('get')
            ->with('config')
            ->willReturn(
                [
                    'mezzio-authorization-rbac' => [
                        'roles' => [],
                        'permissions' => [],
                    ],
                ]
            );
        $container->expects(self::once())
            ->method('has')
            ->with(LaminasRbacAssertionInterface::class)
            ->willReturn(false);

        $factory = new LaminasRbacFactory();

        assert($container instanceof ContainerInterface);
        $laminasRbac = $factory($container);
        self::assertInstanceOf(LaminasRbac::class, $laminasRbac);
    }

    /**
     * @throws \PHPUnit\Framework\Exception
     */
    public function testFactoryWithEmptyRolesPermissionsWithAssertionException(): void
    {
        $container = $this->getMockBuilder(ContainerInterface::class)
            ->disableOriginalConstructor()
            ->getMock();
        $container->expects(self::once())
            ->method('get')
            ->with('config')
            ->willReturn(
                [
                    'mezzio-authorization-rbac' => [
                        'roles' => [],
                        'permissions' => [],
                    ],
                ]
            );
        $container->expects(self::once())
            ->method('has')
            ->with(LaminasRbacAssertionInterface::class)
            ->willThrowException(new ServiceNotFoundException('test'));

        $factory = new LaminasRbacFactory();

        $this->expectException(Exception\InvalidConfigException::class);
        $this->expectExceptionMessage('Could not load the LaminasRbacAssertionInterface');
        $this->expectExceptionCode(0);

        assert($container instanceof ContainerInterface);
        $factory($container);
    }

    /**
     * @throws \PHPUnit\Framework\Exception
     * @throws InvalidArgumentException
     */
    public function testFactoryWithEmptyRolesPermissionsWithAssertion(): void
    {
        $interface = $this->createMock(LaminasRbacAssertionInterface::class);
        $container = $this->getMockBuilder(ContainerInterface::class)
            ->disableOriginalConstructor()
            ->getMock();
        $container->expects(self::exactly(2))
            ->method('get')
            ->withConsecutive(['config'], [LaminasRbacAssertionInterface::class])
            ->willReturnOnConsecutiveCalls(
                [
                    'mezzio-authorization-rbac' => [
                        'roles' => [],
                        'permissions' => [],
                    ],
                ],
                $interface
            );
        $container->expects(self::once())
            ->method('has')
            ->with(LaminasRbacAssertionInterface::class)
            ->willReturn(true);

        $factory = new LaminasRbacFactory();

        assert($container instanceof ContainerInterface);
        $laminasRbac = $factory($container);
        self::assertInstanceOf(LaminasRbac::class, $laminasRbac);
    }

    /**
     * @throws \PHPUnit\Framework\Exception
     * @throws InvalidArgumentException
     */
    public function testFactoryWithoutAssertion(): void
    {
        $container = $this->getMockBuilder(ContainerInterface::class)
            ->disableOriginalConstructor()
            ->getMock();
        $container->expects(self::once())
            ->method('get')
            ->with('config')
            ->willReturn(
                [
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
                ]
            );
        $container->expects(self::once())
            ->method('has')
            ->with(LaminasRbacAssertionInterface::class)
            ->willReturn(false);

        $factory = new LaminasRbacFactory();

        assert($container instanceof ContainerInterface);
        $laminasRbac = $factory($container);
        self::assertInstanceOf(LaminasRbac::class, $laminasRbac);
    }

    /**
     * @throws \PHPUnit\Framework\Exception
     * @throws InvalidArgumentException
     */
    public function testFactoryWithAssertion(): void
    {
        $interface = $this->createMock(LaminasRbacAssertionInterface::class);
        $container = $this->getMockBuilder(ContainerInterface::class)
            ->disableOriginalConstructor()
            ->getMock();
        $container->expects(self::exactly(2))
            ->method('get')
            ->withConsecutive(['config'], [LaminasRbacAssertionInterface::class])
            ->willReturnOnConsecutiveCalls(
                [
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
                ],
                $interface
            );
        $container->expects(self::once())
            ->method('has')
            ->with(LaminasRbacAssertionInterface::class)
            ->willReturn(true);

        $factory = new LaminasRbacFactory();

        assert($container instanceof ContainerInterface);
        $laminasRbac = $factory($container);
        self::assertInstanceOf(LaminasRbac::class, $laminasRbac);
    }

    /**
     * @throws \PHPUnit\Framework\Exception
     */
    public function testFactoryWithInvalidRole(): void
    {
        $container = $this->getMockBuilder(ContainerInterface::class)
            ->disableOriginalConstructor()
            ->getMock();
        $container->expects(self::once())
            ->method('get')
            ->with('config')
            ->willReturn(
                [
                    'mezzio-authorization-rbac' => [
                        'roles' => [
                            1 => [],
                        ],
                        'permissions' => [],
                    ],
                ]
            );
        $container->expects(self::never())
            ->method('has');

        $factory = new LaminasRbacFactory();

        $this->expectException(Exception\InvalidConfigException::class);
        $this->expectExceptionMessage('Role must be a string or implement Laminas\Permissions\Rbac\RoleInterface');
        $this->expectExceptionCode(0);

        assert($container instanceof ContainerInterface);
        $factory($container);
    }

    /**
     * @throws \PHPUnit\Framework\Exception
     */
    public function testFactoryWithUnknownRole(): void
    {
        $container = $this->getMockBuilder(ContainerInterface::class)
            ->disableOriginalConstructor()
            ->getMock();
        $container->expects(self::once())
            ->method('get')
            ->with('config')
            ->willReturn(
                [
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
                ]
            );
        $container->expects(self::never())
            ->method('has');

        $factory = new LaminasRbacFactory();

        $this->expectException(Exception\InvalidConfigException::class);
        $this->expectExceptionMessage('No role with name "contributor" could be found');
        $this->expectExceptionCode(0);

        assert($container instanceof ContainerInterface);
        $factory($container);
    }

    /**
     * @throws \PHPUnit\Framework\Exception
     * @throws InvalidArgumentException
     * @throws RuntimeException
     * @throws ReflectionException
     */
    public function testFactoryWithReflection(): void
    {
        $interface = $this->createMock(LaminasRbacAssertionInterface::class);

        $container = $this->getMockBuilder(ContainerInterface::class)
            ->disableOriginalConstructor()
            ->getMock();
        $container->expects(self::exactly(2))
            ->method('get')
            ->withConsecutive(['config'], [LaminasRbacAssertionInterface::class])
            ->willReturnOnConsecutiveCalls(
                [
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
                ],
                $interface
            );
        $container->expects(self::once())
            ->method('has')
            ->with(LaminasRbacAssertionInterface::class)
            ->willReturn(true);

        $role1 = $this->getMockBuilder(RoleInterface::class)
            ->disableOriginalConstructor()
            ->getMock();
        $role1->expects(self::exactly(2))
            ->method('addPermission')
            ->withConsecutive(['admin.dashboard'], ['admin.posts']);

        $role2 = $this->getMockBuilder(RoleInterface::class)
            ->disableOriginalConstructor()
            ->getMock();
        $role2->expects(self::once())
            ->method('addPermission')
            ->with('admin.publish');

        $role3 = $this->getMockBuilder(RoleInterface::class)
            ->disableOriginalConstructor()
            ->getMock();
        $role3->expects(self::once())
            ->method('addPermission')
            ->with('admin.settings');

        $rbac = $this->getMockBuilder(Rbac::class)
            ->disableOriginalConstructor()
            ->getMock();
        $rbac->expects(self::once())
            ->method('setCreateMissingRoles')
            ->with(true);
        $rbac->expects(self::exactly(3))
            ->method('addRole')
            ->withConsecutive(['administrator', []], ['editor', ['administrator']], ['contributor', ['editor']]);
        $rbac->expects(self::exactly(4))
            ->method('getRole')
            ->withConsecutive(['contributor'], ['contributor'], ['editor'], ['administrator'])
            ->willReturnOnConsecutiveCalls($role1, $role1, $role2, $role3);
        $rbac->expects(self::once())
            ->method('isGranted')
            ->with('contributor', 'admin.settings', $interface)
            ->willReturn(true);

        $factory = new LaminasRbacFactory();

        $rbacProp = new ReflectionProperty($factory, 'rbac');
        $rbacProp->setAccessible(true);
        $rbacProp->setValue($factory, $rbac);

        assert($container instanceof ContainerInterface);
        $laminasRbac = $factory($container);
        self::assertInstanceOf(LaminasRbac::class, $laminasRbac);

        self::assertTrue($laminasRbac->isGranted('contributor', 'admin.settings', null, null));
    }
}
