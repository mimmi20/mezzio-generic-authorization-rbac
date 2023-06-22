<?php
/**
 * This file is part of the mimmi20/mezzio-generic-authorization-rbac package.
 *
 * Copyright (c) 2020-2023, Thomas Mueller <mimmi20@live.de>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

declare(strict_types = 1);

namespace Mimmi20\Mezzio\GenericAuthorization\Rbac;

use Laminas\Permissions\Rbac\Exception\InvalidArgumentException;
use Laminas\Permissions\Rbac\Rbac;
use Mezzio\GenericAuthorization\AuthorizationInterface;
use Mezzio\GenericAuthorization\Exception;
use Psr\Http\Message\ServerRequestInterface;

final class LaminasRbac implements AuthorizationInterface
{
    /** @throws void */
    public function __construct(
        private readonly Rbac $rbac,
        private LaminasRbacAssertionInterface | null $assertion = null,
    ) {
        // nothing to do
    }

    /**
     * Check if a role is granted for a resource
     *
     * @throws Exception\RuntimeException
     *
     * @phpcsSuppress SlevomatCodingStandard.Functions.UnusedParameter.UnusedParameter
     */
    public function isGranted(
        string | null $role = null,
        string | null $resource = null,
        string | null $privilege = null,
        ServerRequestInterface | null $request = null,
    ): bool {
        // RBAC requires a role and a resource
        if ($role === null || $resource === null) {
            return true;
        }

        if ($this->assertion !== null && $request !== null) {
            $this->assertion->setRequest($request);
        }

        try {
            return $this->rbac->isGranted($role, $resource, $this->assertion);
        } catch (InvalidArgumentException $e) {
            throw new Exception\RuntimeException('Could not check Authorization', 0, $e);
        }
    }
}
