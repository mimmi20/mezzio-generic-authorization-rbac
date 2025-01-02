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

use Mimmi20\Mezzio\GenericAuthorization\AuthorizationInterface;

final class ConfigProvider
{
    /**
     * @return array<string, array<string, array<string, string>>>
     *
     * @throws void
     */
    public function __invoke(): array
    {
        return [
            'dependencies' => $this->getDependencies(),
        ];
    }

    /**
     * @return array<string, array<string, string>>
     *
     * @throws void
     *
     * @api
     */
    public function getDependencies(): array
    {
        return [
            'aliases' => [
                AuthorizationInterface::class => LaminasRbac::class,
            ],
            'factories' => [
                LaminasRbac::class => LaminasRbacFactory::class,
            ],
        ];
    }
}
