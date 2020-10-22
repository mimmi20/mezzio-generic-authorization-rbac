<?php



declare(strict_types=1);

namespace Mezzio\GenericAuthorization\Rbac;

use Laminas\Permissions\Rbac\AssertionInterface;
use Laminas\Permissions\Rbac\Rbac;
use Mezzio\GenericAuthorization\AuthorizationInterface;
use Mezzio\GenericAuthorization\Exception;
use Mezzio\Router\RouteResult;
use Psr\Http\Message\ServerRequestInterface;

use function sprintf;

class LaminasRbac implements AuthorizationInterface
{
    /**
     * @var Rbac
     */
    private $rbac;

    /**
     * @var null|AssertionInterface
     */
    private $assertion;

    public function __construct(Rbac $rbac, LaminasRbacAssertionInterface $assertion = null)
    {
        $this->rbac = $rbac;
        $this->assertion = $assertion;
    }

    /**
     * {@inheritDoc}
     *
     * @throws Exception\RuntimeException
     */
    public function isGranted(string $role, string $resource, ?ServerRequestInterface $request = null) : bool
    {
        if (null !== $this->assertion && null !== $request) {
            $this->assertion->setRequest($request);
        }

        return $this->rbac->isGranted($role, $resource, $this->assertion);
    }
}
