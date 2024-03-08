<?php

namespace App\Security;

use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Security;
use Symfony\Component\Security\Http\Authenticator\AbstractLoginFormAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\CsrfTokenBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\RememberMeBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Credentials\PasswordCredentials;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Util\TargetPathTrait;

class UserAuthenticator extends AbstractLoginFormAuthenticator
{
    use TargetPathTrait;

    public const LOGIN_ROUTE = 'app_login';

    public function __construct(private UrlGeneratorInterface $urlGenerator)
    {
    }

    public function authenticate(Request $request): Passport
    {
        $email = $request->request->get('email', '');

        $request->getSession()->set(Security::LAST_USERNAME, $email);

        return new Passport(
            new UserBadge($email),
            new PasswordCredentials($request->request->get('password', '')),
            [
                new CsrfTokenBadge('authenticate', $request->request->get('_csrf_token')),
                new RememberMeBadge(),
            ]
        );
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
    {
        if ($targetPath = $this->getTargetPath($request->getSession(), $firewallName)) {
            return new RedirectResponse($targetPath);
        }

        $user = $token->getUser();

        // Redirection en fonction du rôle de l'utilisateur
        if ($user->getRoleUser() === "Administrateur") {
            // Si l'utilisateur est un admin, redirige-le vers l'accueil sans condition
            return new RedirectResponse($this->urlGenerator->generate('app_home'));
        } elseif ($user->getRoleUser() === "Employee") {
            // Si l'utilisateur est un employé, vérifiez dans quel département il se trouve
            $department = $user->getDepartement(); // Supposons que getDepartment() renvoie le département de l'employé

            if ($department === null) {
                // Si le département n'est pas défini, redirigez l'employé vers la page de sélection du département
                return new RedirectResponse($this->urlGenerator->generate('app_login'));
            } else {
                // Vérifiez le département de l'employé et redirigez en conséquence
                switch ($department) {
                    case "fournisseur":
                        return new RedirectResponse($this->urlGenerator->generate('app_home_eployee'));
                    case "livraison":
                        return new RedirectResponse($this->urlGenerator->generate('app_home_eployee'));
                    case "produit":
                        return new RedirectResponse($this->urlGenerator->generate('app_home_eployee'));
                    case "facture":
                        return new RedirectResponse($this->urlGenerator->generate('app_home_eployee'));
                    case "client":
                        return new RedirectResponse($this->urlGenerator->generate('app_home_eployee'));
                }
            }
        } else {
            // Pour les autres utilisateurs non admin et non employés, les rediriger vers l'accueil par défaut
            return new RedirectResponse($this->urlGenerator->generate('app_home'));
        }
    }



    protected function getLoginUrl(Request $request): string
    {
        return $this->urlGenerator->generate(self::LOGIN_ROUTE);
    }
    /*
     if ($targetPath = $this->getTargetPath($request->getSession(), $firewallName)) {
            return new RedirectResponse($targetPath);
        }
        $user = $token->getUser();

        if ($user->getIsBanned()==1) {
            throw new CustomUserMessageAuthenticationException('Your account has been banned.');
            return new RedirectResponse($this->urlGenerator->generate('app_ban'));
        }else   if ($user->IsVerified() == 0) {
            return new RedirectResponse($this->urlGenerator->generate('app_login'));
        }
        else{

       if($token->getUser()->getRole()=="Driver" || $token->getUser()->getRole()=="Supplier" || $token->getUser()->getRole()=="Client" || $token->getUser()->getRole()=="User")
         return new RedirectResponse($this->urlGenerator->generate('app_home'));
      else
        return new RedirectResponse($this->urlGenerator->generate('app_user_index'));

    }
     */

}
