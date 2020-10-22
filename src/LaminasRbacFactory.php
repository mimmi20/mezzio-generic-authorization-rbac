<?php



declare(strict_types=1);

namespace Mezzio\GenericAuthorization\Rbac;

use Laminas\Permissions\Rbac\Exception\ExceptionInterface as RbacExceptionInterface;
use Laminas\Permissions\Rbac\Rbac;
use Mezzio\GenericAuthorization\AuthorizationInterface;
use Mezzio\GenericAuthorization\Exception;
use Psr\Container\ContainerInterface;

use function sprintf;

class LaminasRbacFactory
{
    /**
     * @throws Exception\InvalidConfigException
     */
    public function __invoke(ContainerInterface $container) : AuthorizationInterface
    {
        $config = $container->get('config')['mezzio-authorization-rbac'] ?? null;
        if (null === $config) {
            throw new Exception\InvalidConfigException(sprintf(
                'Cannot create %s instance; no "mezzio-authorization-rbac" config key present',
                LaminasRbac::class
            ));
        }
        if (! isset($config['roles'])) {
            throw new Exception\InvalidConfigException(sprintf(
                'Cannot create %s instance; no mezzio-authorization-rbac.roles configured',
                LaminasRbac::class
            ));
        }
        if (! isset($config['permissions'])) {
            throw new Exception\InvalidConfigException(sprintf(
                'Cannot create %s instance; no mezzio-authorization-rbac.permissions configured',
                LaminasRbac::class
            ));
        }

        $rbac = new Rbac();
        $this->injectRoles($rbac, $config['roles']);
        $this->injectPermissions($rbac, $config['permissions']);

        $assertion = $container->has(LaminasRbacAssertionInterface::class)
            ? $container->get(LaminasRbacAssertionInterface::class)
            : ($container->has(\Zend\Expressive\Authorization\Rbac\ZendRbacAssertionInterface::class)
                ? $container->get(\Zend\Expressive\Authorization\Rbac\ZendRbacAssertionInterface::class)
                : null);

        return new LaminasRbac($rbac, $assertion);
    }

    /**
     * @throws Exception\InvalidConfigException
     */
    private function injectRoles(Rbac $rbac, array $roles) : void
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
     * @throws Exception\InvalidConfigException
     */
    private function injectPermissions(Rbac $rbac, array $specification) : void
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
