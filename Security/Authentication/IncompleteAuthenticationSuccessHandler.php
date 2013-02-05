<?php

/*
 * This file is part of the Symfony package.
 *
 * (c) Fabien Potencier <fabien@symfony.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FOS\UserBundle\Security\Authentication;

use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Http\HttpUtils;
use FOS\UserBundle\Security\Authentication\Token\IncompleteUserToken;
use Symfony\Component\Security\Http\Authentication\DefaultAuthenticationSuccessHandler;

/**
 * Class with the default authentication success handling logic.
 *
 * Can be optionally be extended from by the developer to alter the behaviour
 * while keeping the default behaviour.
 *
 * @author Fabien Potencier <fabien@symfony.com>
 * @author Johannes M. Schmitt <schmittjoh@gmail.com>
 * @author Alexander <iam.asm89@gmail.com>
 */
class IncompleteAuthenticationSuccessHandler extends DefaultAuthenticationSuccessHandler
{
    /**
     * {@inheritDoc}
     */
    public function onAuthenticationSuccess(Request $request, TokenInterface $token)
    {
        if ($token instanceof IncompleteUserToken) {
            $url = $this->httpUtils->generateUri($request, 'fos_user_registration_incomplete');
        } else {
            $url = $this->determineTargetUrl($request);
        }

        return $this->httpUtils->createRedirectResponse($request, $url);
    }
}
