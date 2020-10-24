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
namespace Mezzio\GenericAuthorization\Rbac;

use Laminas\Permissions\Rbac\Exception\InvalidArgumentException;
use Laminas\Permissions\Rbac\Rbac;
use Mezzio\GenericAuthorization\AuthorizationInterface;
use Mezzio\GenericAuthorization\Exception;
use Psr\Http\Message\ServerRequestInterface;

final class LaminasRbac implements AuthorizationInterface
{
    /** @var Rbac */
    private $rbac;

    /** @var LaminasRbacAssertionInterface|null */
    private $assertion;

    /**
     * @param \Laminas\Permissions\Rbac\Rbac                                       $rbac
     * @param \Mezzio\GenericAuthorization\Rbac\LaminasRbacAssertionInterface|null $assertion
     */
    public function __construct(Rbac $rbac, ?LaminasRbacAssertionInterface $assertion = null)
    {
        $this->rbac      = $rbac;
        $this->assertion = $assertion;
    }

    /**
     * Check if a role is granted for a resource
     *
     * @param string                      $role
     * @param string                      $resource
     * @param string|null                 $privilege
     * @param ServerRequestInterface|null $request
     *
     * @throws Exception\RuntimeException
     *
     * @return bool
     */
    public function isGranted(string $role, string $resource, ?string $privilege = null, ?ServerRequestInterface $request = null): bool
    {
        if (null !== $this->assertion && null !== $request) {
            $this->assertion->setRequest($request);
        }

        try {
            return $this->rbac->isGranted($role, $resource, $this->assertion);
        } catch (InvalidArgumentException $e) {
            throw new Exception\RuntimeException('Could not check Authorization', 0, $e);
        }
    }
}
