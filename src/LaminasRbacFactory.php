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

use Laminas\Permissions\Rbac\Exception\ExceptionInterface as RbacExceptionInterface;
use Laminas\Permissions\Rbac\Rbac;
use Laminas\Permissions\Rbac\RoleInterface;
use Mimmi20\Mezzio\GenericAuthorization\AuthorizationInterface;
use Mimmi20\Mezzio\GenericAuthorization\Exception;
use Psr\Container\ContainerExceptionInterface;
use Psr\Container\ContainerInterface;

use function assert;
use function is_array;
use function sprintf;

final class LaminasRbacFactory
{
    private Rbac $rbac;

    /** @throws void */
    public function __construct()
    {
        $this->rbac = new Rbac();
    }

    /** @throws Exception\InvalidConfigException */
    public function __invoke(ContainerInterface $container): AuthorizationInterface
    {
        try {
            $config = $container->get('config');

            assert(is_array($config));
        } catch (ContainerExceptionInterface $e) {
            throw new Exception\InvalidConfigException(
                'Could not read mezzio-authorization-rbac config',
                0,
                $e,
            );
        }

        $config = $config['mezzio-authorization-rbac'] ?? null;

        if (!is_array($config)) {
            throw new Exception\InvalidConfigException(
                sprintf(
                    'Cannot create %s instance; no "mezzio-authorization-rbac" config key present',
                    LaminasRbac::class,
                ),
            );
        }

        if (!isset($config['roles']) || !is_array($config['roles'])) {
            throw new Exception\InvalidConfigException(
                sprintf(
                    'Cannot create %s instance; no mezzio-authorization-rbac.roles configured',
                    LaminasRbac::class,
                ),
            );
        }

        if (!isset($config['permissions']) || !is_array($config['permissions'])) {
            throw new Exception\InvalidConfigException(
                sprintf(
                    'Cannot create %s instance; no mezzio-authorization-rbac.permissions configured',
                    LaminasRbac::class,
                ),
            );
        }

        $this->injectRoles($config['roles']);
        $this->injectPermissions($config['permissions']);

        return new LaminasRbac($this->rbac);
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
                throw new Exception\InvalidConfigException($e->getMessage(), 0, $e);
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
                    throw new Exception\InvalidConfigException($e->getMessage(), 0, $e);
                }
            }
        }
    }
}
