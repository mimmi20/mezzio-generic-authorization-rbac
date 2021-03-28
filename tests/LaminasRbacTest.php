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

namespace MezzioTest\GenericAuthorization\Rbac;

use Laminas\Permissions\Rbac\Exception\InvalidArgumentException;
use Laminas\Permissions\Rbac\Rbac;
use Mezzio\GenericAuthorization\Exception\RuntimeException;
use Mezzio\GenericAuthorization\Rbac\LaminasRbac;
use Mezzio\GenericAuthorization\Rbac\LaminasRbacAssertionInterface;
use PHPUnit\Framework\Exception;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;

use function assert;

final class LaminasRbacTest extends TestCase
{
    /**
     * @throws Exception
     * @throws \SebastianBergmann\RecursionContext\InvalidArgumentException
     */
    public function testConstructorWithoutAssertion(): void
    {
        $rbac = $this->createMock(Rbac::class);

        assert($rbac instanceof Rbac);
        assert($rbac instanceof Rbac);
        $laminasRbac = new LaminasRbac($rbac);
        self::assertInstanceOf(LaminasRbac::class, $laminasRbac);
    }

    /**
     * @throws Exception
     * @throws \SebastianBergmann\RecursionContext\InvalidArgumentException
     */
    public function testConstructorWithAssertion(): void
    {
        $rbac      = $this->createMock(Rbac::class);
        $assertion = $this->createMock(LaminasRbacAssertionInterface::class);

        assert($rbac instanceof Rbac);
        assert($assertion instanceof LaminasRbacAssertionInterface);
        $laminasRbac = new LaminasRbac($rbac, $assertion);
        self::assertInstanceOf(LaminasRbac::class, $laminasRbac);
    }

    /**
     * @throws RuntimeException
     * @throws Exception
     * @throws \SebastianBergmann\RecursionContext\InvalidArgumentException
     */
    public function testIsGrantedWithoutAssertion(): void
    {
        $role     = 'foo';
        $resource = 'bar';

        $rbac = $this->getMockBuilder(Rbac::class)
            ->disableOriginalConstructor()
            ->getMock();
        $rbac->expects(self::once())
            ->method('isGranted')
            ->with($role, $resource, null)
            ->willReturn(true);

        assert($rbac instanceof Rbac);
        $laminasRbac = new LaminasRbac($rbac);

        self::assertTrue($laminasRbac->isGranted($role, $resource));
    }

    /**
     * @throws RuntimeException
     * @throws Exception
     * @throws \SebastianBergmann\RecursionContext\InvalidArgumentException
     */
    public function testIsGrantedWithoutRole(): void
    {
        $rbac = $this->getMockBuilder(Rbac::class)
            ->disableOriginalConstructor()
            ->getMock();
        $rbac->expects(self::never())
            ->method('isGranted');

        assert($rbac instanceof Rbac);
        $laminasRbac = new LaminasRbac($rbac);

        self::assertTrue($laminasRbac->isGranted());
    }

    /**
     * @throws RuntimeException
     * @throws Exception
     * @throws \SebastianBergmann\RecursionContext\InvalidArgumentException
     */
    public function testIsGrantedWithoutResource(): void
    {
        $role = 'foo';

        $rbac = $this->getMockBuilder(Rbac::class)
            ->disableOriginalConstructor()
            ->getMock();
        $rbac->expects(self::never())
            ->method('isGranted');

        assert($rbac instanceof Rbac);
        $laminasRbac = new LaminasRbac($rbac);

        self::assertTrue($laminasRbac->isGranted($role));
    }

    /**
     * @throws RuntimeException
     * @throws Exception
     * @throws \SebastianBergmann\RecursionContext\InvalidArgumentException
     */
    public function testIsGrantedWitAssertion(): void
    {
        $role      = 'foo';
        $resource  = 'bar';
        $assertion = $this->createMock(LaminasRbacAssertionInterface::class);

        $rbac = $this->getMockBuilder(Rbac::class)
            ->disableOriginalConstructor()
            ->getMock();
        $rbac->expects(self::once())
            ->method('isGranted')
            ->with($role, $resource, $assertion)
            ->willReturn(true);

        assert($rbac instanceof Rbac);
        assert($assertion instanceof LaminasRbacAssertionInterface);
        $laminasRbac = new LaminasRbac($rbac, $assertion);

        self::assertTrue($laminasRbac->isGranted($role, $resource));
    }

    /**
     * @throws RuntimeException
     * @throws Exception
     */
    public function testIsGrantedWitAssertionException(): void
    {
        $role      = 'foo';
        $resource  = 'bar';
        $assertion = $this->createMock(LaminasRbacAssertionInterface::class);

        $rbac = $this->getMockBuilder(Rbac::class)
            ->disableOriginalConstructor()
            ->getMock();
        $rbac->expects(self::once())
            ->method('isGranted')
            ->with($role, $resource, $assertion)
            ->willThrowException(new InvalidArgumentException('test'));

        assert($rbac instanceof Rbac);
        assert($assertion instanceof LaminasRbacAssertionInterface);
        $laminasRbac = new LaminasRbac($rbac, $assertion);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Could not check Authorization');
        $this->expectExceptionCode(0);

        $laminasRbac->isGranted($role, $resource);
    }

    /**
     * @throws RuntimeException
     * @throws Exception
     * @throws \SebastianBergmann\RecursionContext\InvalidArgumentException
     */
    public function testIsGrantedWitAssertionAndRequest(): void
    {
        $role     = 'foo';
        $resource = 'bar';

        $request = $this->createMock(ServerRequestInterface::class);

        $assertion = $this->getMockBuilder(LaminasRbacAssertionInterface::class)
            ->disableOriginalConstructor()
            ->getMock();
        $assertion->expects(self::once())
            ->method('setRequest')
            ->with($request);

        $rbac = $this->getMockBuilder(Rbac::class)
            ->disableOriginalConstructor()
            ->getMock();
        $rbac->expects(self::once())
            ->method('isGranted')
            ->with($role, $resource, $assertion)
            ->willReturn(true);

        assert($rbac instanceof Rbac);
        assert($assertion instanceof LaminasRbacAssertionInterface);
        $laminasRbac = new LaminasRbac($rbac, $assertion);

        self::assertTrue($laminasRbac->isGranted($role, $resource, null, $request));
    }
}
