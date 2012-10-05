<?php

/*
 * This file is part of the FOSUserBundle package.
 *
 * (c) FriendsOfSymfony <http://friendsofsymfony.github.com/>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FOS\UserBundle\Security;

use FOS\UserBundle\Model\UserManagerInterface;
use FOS\UserBundle\Model\UserInterface;
use FOS\UserBundle\Security\LoginManagerInterface;
use FOS\UserBundle\Security\Authentication\Token\IncompleteUserToken;
use Symfony\Component\Security\Http\Event\InteractiveLoginEvent;
use Symfony\Component\Security\Core\SecurityContextInterface;

class InteractiveLoginListener
{
    protected $userManager;
    protected $loginManager;
    protected $firewallName;

    public function __construct(UserManagerInterface $userManager, LoginManagerInterface $loginManager, $firewallName)
    {
        $this->userManager = $userManager;
        $this->loginManager = $loginManager;
        $this->firewallName = $firewallName;
    }

    public function onSecurityInteractiveLogin(InteractiveLoginEvent $event)
    {
        $user = $event->getAuthenticationToken()->getUser();

        if ($user instanceof UserInterface) {
            $user->setLastLogin(new \DateTime());
            
            if ($user->getEmail() === null || $user->getUsername() === null) {
                $user->setIncomplete(true);

                $token = new IncompleteUserToken($this->firewallName, $user, $user->getRoles());
                $this->loginManager->loginUser($this->firewallName, $user, null, $token);
            }
            else {
                $this->userManager->updateUser($user);
            }
        }
    }
}
