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

use Laminas\Permissions\Rbac\AssertionInterface;
use Psr\Http\Message\ServerRequestInterface;

interface LaminasRbacAssertionInterface extends AssertionInterface
{
    /** @throws void */
    public function setRequest(ServerRequestInterface $request): void;
}
