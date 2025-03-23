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

use Laminas\Permissions\Rbac\Exception\InvalidArgumentException;
use Laminas\Permissions\Rbac\Rbac;
use Mimmi20\Mezzio\GenericAuthorization\Exception\RuntimeException;
use PHPUnit\Event\NoPreviousThrowableException;
use PHPUnit\Framework\Exception;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;

final class LaminasRbacTest extends TestCase
{
    /**
     * @throws Exception
     * @throws NoPreviousThrowableException
     * @throws \PHPUnit\Framework\MockObject\Exception
     */
    public function testConstructorWithoutAssertion(): void
    {
        $rbac = $this->createMock(Rbac::class);

        $laminasRbac = new LaminasRbac($rbac);

        self::assertInstanceOf(LaminasRbac::class, $laminasRbac);
    }

    /**
     * @throws Exception
     * @throws NoPreviousThrowableException
     * @throws \PHPUnit\Framework\MockObject\Exception
     */
    public function testConstructorWithAssertion(): void
    {
        $rbac = $this->createMock(Rbac::class);

        $laminasRbac = new LaminasRbac($rbac);
        self::assertInstanceOf(LaminasRbac::class, $laminasRbac);
    }

    /**
     * @throws RuntimeException
     * @throws Exception
     * @throws NoPreviousThrowableException
     * @throws \PHPUnit\Framework\MockObject\Exception
     */
    public function testIsGrantedWithoutAssertion(): void
    {
        $role     = 'foo';
        $resource = 'bar';

        $rbac = $this->createMock(Rbac::class);
        $rbac->expects(self::once())
            ->method('isGranted')
            ->with($role, $resource, null)
            ->willReturn(true);

        $laminasRbac = new LaminasRbac($rbac);

        self::assertTrue($laminasRbac->isGranted($role, $resource));
    }

    /**
     * @throws RuntimeException
     * @throws Exception
     * @throws NoPreviousThrowableException
     * @throws \PHPUnit\Framework\MockObject\Exception
     */
    public function testIsGrantedWithoutRole(): void
    {
        $rbac = $this->createMock(Rbac::class);
        $rbac->expects(self::never())
            ->method('isGranted');

        $laminasRbac = new LaminasRbac($rbac);

        self::assertTrue($laminasRbac->isGranted());
    }

    /**
     * @throws RuntimeException
     * @throws Exception
     * @throws NoPreviousThrowableException
     * @throws \PHPUnit\Framework\MockObject\Exception
     */
    public function testIsGrantedWithoutResource(): void
    {
        $role = 'foo';

        $rbac = $this->createMock(Rbac::class);
        $rbac->expects(self::never())
            ->method('isGranted');

        $laminasRbac = new LaminasRbac($rbac);

        self::assertTrue($laminasRbac->isGranted($role));
    }

    /**
     * @throws RuntimeException
     * @throws Exception
     * @throws NoPreviousThrowableException
     * @throws \PHPUnit\Framework\MockObject\Exception
     */
    public function testIsGrantedWitAssertion(): void
    {
        $role      = 'foo';
        $resource  = 'bar';
        $assertion = $this->createMock(LaminasRbacAssertionInterface::class);
        $assertion->expects(self::never())
            ->method('setRequest');

        $rbac = $this->createMock(Rbac::class);
        $rbac->expects(self::once())
            ->method('isGranted')
            ->with($role, $resource, $assertion)
            ->willReturn(true);

        $laminasRbac = new LaminasRbac($rbac);

        self::assertTrue($laminasRbac->isGranted($role, $resource, assertion: $assertion));
    }

    /**
     * @throws RuntimeException
     * @throws Exception
     * @throws NoPreviousThrowableException
     * @throws \PHPUnit\Framework\MockObject\Exception
     */
    public function testIsGrantedWitAssertionException(): void
    {
        $role      = 'foo';
        $resource  = 'bar';
        $assertion = $this->createMock(LaminasRbacAssertionInterface::class);
        $assertion->expects(self::never())
            ->method('setRequest');

        $rbac = $this->createMock(Rbac::class);
        $rbac->expects(self::once())
            ->method('isGranted')
            ->with($role, $resource, $assertion)
            ->willThrowException(new InvalidArgumentException('test'));

        $laminasRbac = new LaminasRbac($rbac);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Could not check Authorization');
        $this->expectExceptionCode(0);

        $laminasRbac->isGranted($role, $resource, assertion: $assertion);
    }

    /**
     * @throws RuntimeException
     * @throws Exception
     * @throws NoPreviousThrowableException
     * @throws \PHPUnit\Framework\MockObject\Exception
     */
    public function testIsGrantedWitAssertionAndRequest(): void
    {
        $role     = 'foo';
        $resource = 'bar';

        $request = $this->createMock(ServerRequestInterface::class);

        $assertion = $this->createMock(LaminasRbacAssertionInterface::class);
        $assertion->expects(self::once())
            ->method('setRequest')
            ->with($request);

        $rbac = $this->createMock(Rbac::class);
        $rbac->expects(self::once())
            ->method('isGranted')
            ->with($role, $resource, $assertion)
            ->willReturn(true);

        $laminasRbac = new LaminasRbac($rbac);

        self::assertTrue(
            $laminasRbac->isGranted($role, $resource, null, $request, assertion: $assertion),
        );
    }
}
