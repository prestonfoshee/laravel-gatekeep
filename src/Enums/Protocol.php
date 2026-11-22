<?php

declare(strict_types=1);

namespace Gatekeep\Enums;

enum Protocol: string
{
    case Saml = 'saml';
    case Oidc = 'oidc';
}
