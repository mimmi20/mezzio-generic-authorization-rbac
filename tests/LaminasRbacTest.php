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

use Laminas\Permissions\Rbac\Exception\InvalidArgumentException;
use Laminas\Permissions\Rbac\Rbac;
use Mezzio\GenericAuthorization\Exception\RuntimeException;
use Mezzio\GenericAuthorization\Rbac\LaminasRbac;
use Mezzio\GenericAuthorization\Rbac\LaminasRbacAssertionInterface;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;

final class LaminasRbacTest extends TestCase
{
    /**
     * @throws \PHPUnit\Framework\ExpectationFailedException
     * @throws \SebastianBergmann\RecursionContext\InvalidArgumentException
     *
     * @return void
     */
    public function testConstructorWithoutAssertion(): void
    {
        $rbac = $this->createMock(Rbac::class);

        /** @var Rbac $rbac */
        $laminasRbac = new LaminasRbac($rbac);
        self::assertInstanceOf(LaminasRbac::class, $laminasRbac);
    }

    /**
     * @throws \PHPUnit\Framework\ExpectationFailedException
     * @throws \SebastianBergmann\RecursionContext\InvalidArgumentException
     *
     * @return void
     */
    public function testConstructorWithAssertion(): void
    {
        $rbac      = $this->createMock(Rbac::class);
        $assertion = $this->createMock(LaminasRbacAssertionInterface::class);

        /** @var Rbac $rbac */
        /** @var LaminasRbacAssertionInterface $assertion */
        $laminasRbac = new LaminasRbac($rbac, $assertion);
        self::assertInstanceOf(LaminasRbac::class, $laminasRbac);
    }

    /**
     * @throws \Mezzio\GenericAuthorization\Exception\RuntimeException
     * @throws \PHPUnit\Framework\ExpectationFailedException
     * @throws \PHPUnit\Framework\MockObject\RuntimeException
     * @throws \SebastianBergmann\RecursionContext\InvalidArgumentException
     *
     * @return void
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

        /** @var Rbac $rbac */
        $laminasRbac = new LaminasRbac($rbac);
        self::assertInstanceOf(LaminasRbac::class, $laminasRbac);

        self::assertTrue($laminasRbac->isGranted($role, $resource));
    }

    /**
     * @throws \Mezzio\GenericAuthorization\Exception\RuntimeException
     * @throws \PHPUnit\Framework\ExpectationFailedException
     * @throws \PHPUnit\Framework\MockObject\RuntimeException
     * @throws \SebastianBergmann\RecursionContext\InvalidArgumentException
     *
     * @return void
     */
    public function testIsNotGrantedRole(): void
    {
        $rbac = $this->getMockBuilder(Rbac::class)
            ->disableOriginalConstructor()
            ->getMock();
        $rbac->expects(self::never())
            ->method('isGranted');

        /** @var Rbac $rbac */
        $laminasRbac = new LaminasRbac($rbac);
        self::assertInstanceOf(LaminasRbac::class, $laminasRbac);

        self::assertFalse($laminasRbac->isGranted());
    }

    /**
     * @throws \Mezzio\GenericAuthorization\Exception\RuntimeException
     * @throws \PHPUnit\Framework\ExpectationFailedException
     * @throws \PHPUnit\Framework\MockObject\RuntimeException
     * @throws \SebastianBergmann\RecursionContext\InvalidArgumentException
     *
     * @return void
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

        /** @var Rbac $rbac */
        /** @var LaminasRbacAssertionInterface $assertion */
        $laminasRbac = new LaminasRbac($rbac, $assertion);
        self::assertInstanceOf(LaminasRbac::class, $laminasRbac);

        self::assertTrue($laminasRbac->isGranted($role, $resource));
    }

    /**
     * @throws \Mezzio\GenericAuthorization\Exception\RuntimeException
     * @throws \PHPUnit\Framework\ExpectationFailedException
     * @throws \PHPUnit\Framework\MockObject\RuntimeException
     * @throws \SebastianBergmann\RecursionContext\InvalidArgumentException
     *
     * @return void
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

        /** @var Rbac $rbac */
        /** @var LaminasRbacAssertionInterface $assertion */
        $laminasRbac = new LaminasRbac($rbac, $assertion);
        self::assertInstanceOf(LaminasRbac::class, $laminasRbac);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Could not check Authorization');

        $laminasRbac->isGranted($role, $resource);
    }

    /**
     * @throws \Mezzio\GenericAuthorization\Exception\RuntimeException
     * @throws \PHPUnit\Framework\ExpectationFailedException
     * @throws \PHPUnit\Framework\MockObject\RuntimeException
     * @throws \SebastianBergmann\RecursionContext\InvalidArgumentException
     *
     * @return void
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

        /** @var Rbac $rbac */
        /** @var LaminasRbacAssertionInterface $assertion */
        $laminasRbac = new LaminasRbac($rbac, $assertion);
        self::assertInstanceOf(LaminasRbac::class, $laminasRbac);

        self::assertTrue($laminasRbac->isGranted($role, $resource, null, $request));
    }
}
