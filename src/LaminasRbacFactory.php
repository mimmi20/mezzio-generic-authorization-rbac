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
use Mezzio\GenericAuthorization\AuthorizationInterface;
use Mezzio\GenericAuthorization\Exception;
use Psr\Container\ContainerExceptionInterface;
use Psr\Container\ContainerInterface;

final class LaminasRbacFactory
{
    /**
     * @param ContainerInterface $container
     *
     * @throws Exception\InvalidConfigException
     *
     * @return AuthorizationInterface
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

        $rbac = new Rbac();
        $this->injectRoles($rbac, $config['roles']);
        $this->injectPermissions($rbac, $config['permissions']);

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

        return new LaminasRbac($rbac, $assertion);
    }

    /**
     * @param Rbac  $rbac
     * @param array $roles
     *
     * @throws Exception\InvalidConfigException
     *
     * @return void
     */
    private function injectRoles(Rbac $rbac, array $roles): void
    {
        $rbac->setCreateMissingRoles(true);

        // Roles and parents
        foreach ($roles as $role => $parents) {
            try {
                $rbac->addRole($role, $parents);
            } catch (RbacExceptionInterface $e) {
                throw new Exception\InvalidConfigException($e->getMessage(), $e->getCode(), $e);
            }
        }
    }

    /**
     * @param Rbac  $rbac
     * @param array $specification
     *
     * @throws Exception\InvalidConfigException
     *
     * @return void
     */
    private function injectPermissions(Rbac $rbac, array $specification): void
    {
        foreach ($specification as $role => $permissions) {
            foreach ($permissions as $permission) {
                try {
                    $rbac->getRole($role)->addPermission($permission);
                } catch (RbacExceptionInterface $e) {
                    throw new Exception\InvalidConfigException($e->getMessage(), $e->getCode(), $e);
                }
            }
        }
    }
}
