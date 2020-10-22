<?php



declare(strict_types=1);

namespace Mezzio\GenericAuthorization\Rbac;

use Laminas\Permissions\Rbac\AssertionInterface;
use Psr\Http\Message\ServerRequestInterface;

interface LaminasRbacAssertionInterface extends AssertionInterface
{
    public function setRequest(ServerRequestInterface $request) : void;
}
