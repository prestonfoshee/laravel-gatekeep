<?php

declare(strict_types=1);

namespace Gatekeep\Saml;

final class SamlSession
{
    public static function requestId(string $connectionId): string
    {
        return 'gatekeep.saml.request_id.'.$connectionId;
    }

    public static function returnTo(string $connectionId): string
    {
        return 'gatekeep.saml.return_to.'.$connectionId;
    }
}
