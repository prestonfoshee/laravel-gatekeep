<?php

declare(strict_types=1);

namespace Gatekeep\Enums;

enum CertificateStatus: string
{
    case Next = 'next';
    case Active = 'active';
    case Retiring = 'retiring';
    case Retired = 'retired';
}
