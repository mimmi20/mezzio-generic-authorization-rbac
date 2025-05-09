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

use Laminas\Permissions\Rbac\Rbac;
use Laminas\Permissions\Rbac\RoleInterface;
use Laminas\ServiceManager\Exception\ServiceNotFoundException;
use Mimmi20\Mezzio\GenericAuthorization\Exception\InvalidConfigException;
use Mimmi20\Mezzio\GenericAuthorization\Exception\RuntimeException;
use PHPUnit\Event\NoPreviousThrowableException;
use PHPUnit\Framework\Exception;
use PHPUnit\Framework\TestCase;
use Psr\Container\ContainerInterface;
use ReflectionException;
use ReflectionProperty;

use function assert;

final class LaminasRbacFactoryTest extends TestCase
{
    /**
     * @throws Exception
     * @throws InvalidConfigException
     * @throws NoPreviousThrowableException
     * @throws \PHPUnit\Framework\MockObject\Exception
     */
    public function testFactoryWithoutConfig(): void
    {
        $container = $this->createMock(ContainerInterface::class);
        $container->expects(self::once())
            ->method('get')
            ->with('config')
            ->willReturn([]);
        $container->expects(self::never())
            ->method('has');

        $factory = new LaminasRbacFactory();

        $this->expectException(InvalidConfigException::class);
        $this->expectExceptionMessage(
            'Cannot create Mimmi20\Mezzio\GenericAuthorization\Rbac\LaminasRbac instance; no "mezzio-authorization-rbac" config key present',
        );
        $this->expectExceptionCode(0);

        assert($container instanceof ContainerInterface);
        $factory($container);
    }

    /**
     * @throws Exception
     * @throws InvalidConfigException
     * @throws NoPreviousThrowableException
     * @throws \PHPUnit\Framework\MockObject\Exception
     */
    public function testFactoryWithConfigException(): void
    {
        $container = $this->createMock(ContainerInterface::class);
        $container->expects(self::once())
            ->method('get')
            ->with('config')
            ->willThrowException(new ServiceNotFoundException('test'));
        $container->expects(self::never())
            ->method('has');

        $factory = new LaminasRbacFactory();

        $this->expectException(InvalidConfigException::class);
        $this->expectExceptionMessage('Could not read mezzio-authorization-rbac config');
        $this->expectExceptionCode(0);

        assert($container instanceof ContainerInterface);
        $factory($container);
    }

    /**
     * @throws Exception
     * @throws InvalidConfigException
     * @throws NoPreviousThrowableException
     * @throws \PHPUnit\Framework\MockObject\Exception
     */
    public function testFactoryWithoutLaminasRbacConfig(): void
    {
        $container = $this->createMock(ContainerInterface::class);
        $container->expects(self::once())
            ->method('get')
            ->with('config')
            ->willReturn(['mezzio-authorization-rbac' => []]);
        $container->expects(self::never())
            ->method('has');

        $factory = new LaminasRbacFactory();

        $this->expectException(InvalidConfigException::class);
        $this->expectExceptionMessage(
            'Cannot create Mimmi20\Mezzio\GenericAuthorization\Rbac\LaminasRbac instance; no mezzio-authorization-rbac.roles configured',
        );
        $this->expectExceptionCode(0);

        assert($container instanceof ContainerInterface);
        $factory($container);
    }

    /**
     * @throws Exception
     * @throws InvalidConfigException
     * @throws NoPreviousThrowableException
     * @throws \PHPUnit\Framework\MockObject\Exception
     */
    public function testFactoryWithoutPermissions(): void
    {
        $container = $this->createMock(ContainerInterface::class);
        $container->expects(self::once())
            ->method('get')
            ->with('config')
            ->willReturn(
                [
                    'mezzio-authorization-rbac' => [
                        'roles' => [],
                    ],
                ],
            );
        $container->expects(self::never())
            ->method('has');

        $factory = new LaminasRbacFactory();

        $this->expectException(InvalidConfigException::class);
        $this->expectExceptionMessage(
            'Cannot create Mimmi20\Mezzio\GenericAuthorization\Rbac\LaminasRbac instance; no mezzio-authorization-rbac.permissions configured',
        );
        $this->expectExceptionCode(0);

        assert($container instanceof ContainerInterface);
        $factory($container);
    }

    /**
     * @throws Exception
     * @throws InvalidConfigException
     * @throws NoPreviousThrowableException
     * @throws \PHPUnit\Framework\MockObject\Exception
     */
    public function testFactoryWithEmptyRolesPermissionsWithoutAssertion(): void
    {
        $container = $this->createMock(ContainerInterface::class);
        $container->expects(self::once())
            ->method('get')
            ->with('config')
            ->willReturn(
                [
                    'mezzio-authorization-rbac' => [
                        'roles' => [],
                        'permissions' => [],
                    ],
                ],
            );
        $container->expects(self::never())
            ->method('has');

        $factory = new LaminasRbacFactory();

        assert($container instanceof ContainerInterface);
        $laminasRbac = $factory($container);
        self::assertInstanceOf(LaminasRbac::class, $laminasRbac);
    }

    /**
     * @throws Exception
     * @throws InvalidConfigException
     * @throws NoPreviousThrowableException
     * @throws \PHPUnit\Framework\MockObject\Exception
     */
    public function testFactoryWithoutAssertion(): void
    {
        $container = $this->createMock(ContainerInterface::class);
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
                ],
            );
        $container->expects(self::never())
            ->method('has');

        $factory = new LaminasRbacFactory();

        assert($container instanceof ContainerInterface);
        $laminasRbac = $factory($container);
        self::assertInstanceOf(LaminasRbac::class, $laminasRbac);
    }

    /**
     * @throws Exception
     * @throws InvalidConfigException
     * @throws NoPreviousThrowableException
     * @throws \PHPUnit\Framework\MockObject\Exception
     */
    public function testFactoryWithInvalidRole(): void
    {
        $container = $this->createMock(ContainerInterface::class);
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
                ],
            );
        $container->expects(self::never())
            ->method('has');

        $factory = new LaminasRbacFactory();

        $this->expectException(InvalidConfigException::class);
        $this->expectExceptionMessage(
            'Role must be a string or implement Laminas\Permissions\Rbac\RoleInterface',
        );
        $this->expectExceptionCode(0);

        assert($container instanceof ContainerInterface);
        $factory($container);
    }

    /**
     * @throws Exception
     * @throws InvalidConfigException
     * @throws NoPreviousThrowableException
     * @throws \PHPUnit\Framework\MockObject\Exception
     */
    public function testFactoryWithUnknownRole(): void
    {
        $container = $this->createMock(ContainerInterface::class);
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
                ],
            );
        $container->expects(self::never())
            ->method('has');

        $factory = new LaminasRbacFactory();

        $this->expectException(InvalidConfigException::class);
        $this->expectExceptionMessage('No role with name "contributor" could be found');
        $this->expectExceptionCode(0);

        assert($container instanceof ContainerInterface);
        $factory($container);
    }

    /**
     * @throws Exception
     * @throws RuntimeException
     * @throws ReflectionException
     * @throws InvalidConfigException
     * @throws NoPreviousThrowableException
     * @throws \PHPUnit\Framework\MockObject\Exception
     */
    public function testFactoryWithReflection(): void
    {
        $interface = $this->createMock(LaminasRbacAssertionInterface::class);
        $interface->expects(self::never())
            ->method('setRequest');

        $container = $this->createMock(ContainerInterface::class);
        $container->expects(self::once())
            ->method('get')
            ->with('config')
            ->willReturn([
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
        $container->expects(self::never())
            ->method('has');

        $role1   = $this->createMock(RoleInterface::class);
        $matcher = self::exactly(2);
        $role1->expects($matcher)
            ->method('addPermission')
            ->willReturnCallback(
                static function (string $name) use ($matcher): void {
                    match ($matcher->numberOfInvocations()) {
                        2 => self::assertSame('admin.posts', $name),
                        default => self::assertSame('admin.dashboard', $name),
                    };
                },
            );

        $role2 = $this->createMock(RoleInterface::class);
        $role2->expects(self::once())
            ->method('addPermission')
            ->with('admin.publish');

        $role3 = $this->createMock(RoleInterface::class);
        $role3->expects(self::once())
            ->method('addPermission')
            ->with('admin.settings');

        $rbac = $this->createMock(Rbac::class);
        $rbac->expects(self::once())
            ->method('setCreateMissingRoles')
            ->with(true);
        $matcher = self::exactly(3);
        $rbac->expects($matcher)
            ->method('addRole')
            ->willReturnCallback(
                static function (string | RoleInterface $role, array | RoleInterface | null $parents = null) use ($matcher): void {
                    match ($matcher->numberOfInvocations()) {
                        1 => self::assertSame('administrator', $role),
                        2 => self::assertSame('editor', $role),
                        default => self::assertSame('contributor', $role),
                    };

                    match ($matcher->numberOfInvocations()) {
                        1 => self::assertSame([], $parents),
                        2 => self::assertSame(['administrator'], $parents),
                        default => self::assertSame(['editor'], $parents),
                    };
                },
            );
        $matcher = self::exactly(4);
        $rbac->expects($matcher)
            ->method('getRole')
            ->willReturnCallback(
                static function (string $roleName) use ($matcher, $role1, $role2, $role3): RoleInterface {
                    match ($matcher->numberOfInvocations()) {
                        3 => self::assertSame('editor', $roleName),
                        4 => self::assertSame('administrator', $roleName),
                        default => self::assertSame('contributor', $roleName),
                    };

                    return match ($matcher->numberOfInvocations()) {
                        3 => $role2,
                        4 => $role3,
                        default => $role1,
                    };
                },
            );
        $rbac->expects(self::once())
            ->method('isGranted')
            ->with('contributor', 'admin.settings', $interface)
            ->willReturn(true);

        $factory = new LaminasRbacFactory();

        $rbacProp = new ReflectionProperty($factory, 'rbac');
        $rbacProp->setValue($factory, $rbac);

        assert($container instanceof ContainerInterface);
        $laminasRbac = $factory($container);
        self::assertInstanceOf(LaminasRbac::class, $laminasRbac);

        self::assertTrue(
            $laminasRbac->isGranted('contributor', 'admin.settings', null, assertion: $interface),
        );
    }
}
