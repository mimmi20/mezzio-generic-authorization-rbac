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
namespace MezzioTest\GenericAuthorization\Rbac;

use Laminas\Permissions\Rbac\Rbac;
use Mezzio\GenericAuthorization\Exception;
use Mezzio\GenericAuthorization\Rbac\LaminasRbac;
use Mezzio\GenericAuthorization\Rbac\LaminasRbacAssertionInterface;
use Mezzio\Router\Route;
use Mezzio\Router\RouteResult;
use PHPUnit\Framework\TestCase;
use Prophecy\Prophecy\ObjectProphecy;
use Psr\Http\Message\ServerRequestInterface;

final class LaminasRbacTest extends TestCase
{
    /** @var ObjectProphecy|Rbac */
    private $rbac;

    /** @var LaminasRbacAssertionInterface|ObjectProphecy */
    private $assertion;

    /**
     * @return void
     */
    protected function setUp(): void
    {
        $this->rbac      = $this->prophesize(Rbac::class);
        $this->assertion = $this->prophesize(LaminasRbacAssertionInterface::class);
    }

    /**
     * @return void
     */
    public function testConstructorWithoutAssertion(): void
    {
        $laminasRbac = new LaminasRbac($this->rbac->reveal());
        self::assertInstanceOf(LaminasRbac::class, $laminasRbac);
    }

    /**
     * @return void
     */
    public function testConstructorWithAssertion(): void
    {
        $laminasRbac = new LaminasRbac($this->rbac->reveal(), $this->assertion->reveal());
        self::assertInstanceOf(LaminasRbac::class, $laminasRbac);
    }

    /**
     * @return void
     */
    public function testIsGrantedWithoutRouteResult(): void
    {
        $laminasRbac = new LaminasRbac($this->rbac->reveal(), $this->assertion->reveal());

        $request = $this->prophesize(ServerRequestInterface::class);
        $request->getAttribute(RouteResult::class, false)->willReturn(false);

        $this->expectException(Exception\RuntimeException::class);
        $laminasRbac->isGranted('foo', $request->reveal());
    }

    /**
     * @return void
     */
    public function testIsGrantedWithoutAssertion(): void
    {
        $this->rbac->isGranted('foo', 'home', null)->willReturn(true);
        $laminasRbac = new LaminasRbac($this->rbac->reveal());

        $routeResult = $this->getSuccessRouteResult('home');

        $request = $this->prophesize(ServerRequestInterface::class);
        $request->getAttribute(RouteResult::class, false)->willReturn($routeResult);

        $result = $laminasRbac->isGranted('foo', $request->reveal());
        self::assertTrue($result);
    }

    /**
     * @return void
     */
    public function testIsNotGrantedWithoutAssertion(): void
    {
        $this->rbac->isGranted('foo', 'home', null)->willReturn(false);
        $laminasRbac = new LaminasRbac($this->rbac->reveal());

        $routeResult = $this->getSuccessRouteResult('home');

        $request = $this->prophesize(ServerRequestInterface::class);
        $request->getAttribute(RouteResult::class, false)->willReturn($routeResult);

        $result = $laminasRbac->isGranted('foo', $request->reveal());
        self::assertFalse($result);
    }

    /**
     * @return void
     */
    public function testIsGrantedWitAssertion(): void
    {
        $routeResult = $this->getSuccessRouteResult('home');

        $request = $this->prophesize(ServerRequestInterface::class);
        $request->getAttribute(RouteResult::class, false)->willReturn($routeResult);

        $this->rbac->isGranted('foo', 'home', $this->assertion->reveal())->willReturn(true);

        $laminasRbac = new LaminasRbac($this->rbac->reveal(), $this->assertion->reveal());

        $result = $laminasRbac->isGranted('foo', $request->reveal());
        self::assertTrue($result);
        $this->assertion->setRequest($request->reveal())->shouldBeCalled();
    }

    /**
     * @return void
     */
    public function testIsNotGrantedWitAssertion(): void
    {
        $routeResult = $this->getSuccessRouteResult('home');

        $request = $this->prophesize(ServerRequestInterface::class);
        $request->getAttribute(RouteResult::class, false)->willReturn($routeResult);

        $this->rbac->isGranted('foo', 'home', $this->assertion->reveal())->willReturn(false);

        $laminasRbac = new LaminasRbac($this->rbac->reveal(), $this->assertion->reveal());

        $result = $laminasRbac->isGranted('foo', $request->reveal());
        self::assertFalse($result);
        $this->assertion->setRequest($request->reveal())->shouldBeCalled();
    }

    /**
     * @return void
     */
    public function testIsGrantedWithFailedRouting(): void
    {
        $routeResult = $this->getFailureRouteResult(Route::HTTP_METHOD_ANY);

        $request = $this->prophesize(ServerRequestInterface::class);
        $request->getAttribute(RouteResult::class, false)->willReturn($routeResult);

        $laminasRbac = new LaminasRbac($this->rbac->reveal());

        $result = $laminasRbac->isGranted('foo', $request->reveal());
        self::assertTrue($result);
    }

    /**
     * @param string $routeName
     *
     * @return \Mezzio\Router\RouteResult
     */
    private function getSuccessRouteResult(string $routeName): RouteResult
    {
        $route = $this->prophesize(Route::class);
        $route->getName()->willReturn($routeName);

        return RouteResult::fromRoute($route->reveal());
    }

    /**
     * @param array|null $methods
     *
     * @return \Mezzio\Router\RouteResult
     */
    private function getFailureRouteResult(?array $methods): RouteResult
    {
        return RouteResult::fromRouteFailure($methods);
    }
}
