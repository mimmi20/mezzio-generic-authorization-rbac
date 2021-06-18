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

namespace Mezzio\GenericAuthorization\Rbac;

use Laminas\Permissions\Rbac\Exception\ExceptionInterface as RbacExceptionInterface;
use Laminas\Permissions\Rbac\Rbac;
use Laminas\Permissions\Rbac\RoleInterface;
use Mezzio\GenericAuthorization\AuthorizationInterface;
use Mezzio\GenericAuthorization\Exception;
use Psr\Container\ContainerExceptionInterface;
use Psr\Container\ContainerInterface;

use function sprintf;

final class LaminasRbacFactory
{
    private Rbac $rbac;

    public function __construct()
    {
        $this->rbac = new Rbac();
    }

    /**
     * @throws Exception\InvalidConfigException
     */
    public function __invoke(ContainerInterface $container): AuthorizationInterface
    {
        try {
            $config = $container->get('config')['mezzio-authorization-rbac'] ?? null;
        } catch (ContainerExceptionInterface $e) {
            throw new Exception\InvalidConfigException(
                'Could not read mezzio-authorization-rbac config',
                0,
                $e
            );
        }

        if (null === $config) {
            throw new Exception\InvalidConfigException(
                sprintf(
                    'Cannot create %s instance; no "mezzio-authorization-rbac" config key present',
                    LaminasRbac::class
                )
            );
        }

        if (!isset($config['roles'])) {
            throw new Exception\InvalidConfigException(
                sprintf(
                    'Cannot create %s instance; no mezzio-authorization-rbac.roles configured',
                    LaminasRbac::class
                )
            );
        }

        if (!isset($config['permissions'])) {
            throw new Exception\InvalidConfigException(
                sprintf(
                    'Cannot create %s instance; no mezzio-authorization-rbac.permissions configured',
                    LaminasRbac::class
                )
            );
        }

        $this->injectRoles($config['roles']);
        $this->injectPermissions($config['permissions']);

        try {
            $assertion = $container->has(LaminasRbacAssertionInterface::class)
                ? $container->get(LaminasRbacAssertionInterface::class)
                : null;
        } catch (ContainerExceptionInterface $e) {
            throw new Exception\InvalidConfigException(
                'Could not load the LaminasRbacAssertionInterface',
                0,
                $e
            );
        }

        return new LaminasRbac($this->rbac, $assertion);
    }

    /**
     * @param array<string, (array<mixed>|RoleInterface|null)> $roles
     *
     * @throws Exception\InvalidConfigException
     */
    private function injectRoles(array $roles): void
    {
        $this->rbac->setCreateMissingRoles(true);

        // Roles and parents
        foreach ($roles as $role => $parents) {
            try {
                $this->rbac->addRole($role, $parents);
            } catch (RbacExceptionInterface $e) {
                throw new Exception\InvalidConfigException($e->getMessage(), $e->getCode(), $e);
            }
        }
    }

    /**
     * @param array<string, array<string>> $specification
     *
     * @throws Exception\InvalidConfigException
     */
    private function injectPermissions(array $specification): void
    {
        foreach ($specification as $role => $permissions) {
            foreach ($permissions as $permission) {
                try {
                    $this->rbac->getRole($role)->addPermission($permission);
                } catch (RbacExceptionInterface $e) {
                    throw new Exception\InvalidConfigException($e->getMessage(), $e->getCode(), $e);
                }
            }
        }
    }
}
