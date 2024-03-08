<?php

namespace App\Controller;

use App\Entity\User;
use App\Form\UserType;
use App\Repository\UserRepository;
use App\Security\EmailVerifier;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Security\Core\Encoder\UserPasswordEncoderInterface;
use Symfony\Component\Mime\Email;
use Symfony\Component\Mailer\MailerInterface;
use Symfony\Bridge\Twig\Mime\TemplatedEmail;
use Symfony\Component\Form\FormError;
use Symfony\Component\HttpClient\HttpClient;
use Symfony\Component\Form\FormInterface;;

use Symfony\Contracts\HttpClient\HttpClientInterface;
use SymfonyCasts\Bundle\VerifyEmail\Exception\VerifyEmailExceptionInterface;

class UserController extends AbstractController
{
    private EmailVerifier $emailVerifier;
    private HttpClientInterface $httpClient;

    #[Route('/home', name: 'app_home')]
    public function index(UserRepository $userRepository): Response
    {
        return $this->render('admin/home/home.html.twig', [
            'tableau' => $userRepository->findAll(),
        ]);
    }

    #[Route('/tables', name: 'app_tables', methods: ['GET'])]
    public function show(UserRepository $repo): Response
    {
        $result = $repo->findAll();
        return $this->render('admin/tables/tables.html.twig', [
            'tableau' => $result,
        ]);
    }

    private $mailer;

    public function __construct(MailerInterface $mailer, EmailVerifier $emailVerifier, HttpClientInterface $httpClient)
    {
        $this->mailer = $mailer;
        $this->emailVerifier = $emailVerifier;
        $this->httpClient = $httpClient;
    }

    #[Route('/register', name: 'app_register', methods: ['GET', 'POST'])]
    public function register(Request $request, EntityManagerInterface $entityManager, UserPasswordEncoderInterface $passwordEncoder, MailerInterface $mailer): Response
    {
        $user = new User();
        $form = $this->createForm(UserType::class, $user);
        $form->handleRequest($request);

        if ($form->isSubmitted() && $form->isValid()) {
            if (!$this->validateRecaptcha($request)) {
                $form->addError(new FormError('CAPTCHA validation failed.'));
                return $this->renderForm('admin/register/register.html.twig', [
                    'user' => $user,
                    'form' => $form,
                ]);
            }

            $data = $form->getData();
            $user->setEmail($data->getEmail());
            $user->setPassword($passwordEncoder->encodePassword($user, $data->getPassword()));

            $entityManager->persist($user);
            $entityManager->flush();

            // Envoi de l'e-mail de confirmation
            $email = (new TemplatedEmail())
                ->from('ERP@gmail.com')
                ->to($data->getEmail())
                ->subject('Confirmation de création de compte')
                ->htmlTemplate('emailconfirmation.html.twig')
                ->context([
                    'user' => $user,
                ]);

            $mailer->send($email);

            return $this->redirectToRoute('app_tables', [], Response::HTTP_SEE_OTHER);
        }

        return $this->renderForm('admin/register/register.html.twig', [
            'user' => $user,
            'form' => $form,
        ]);
    }

    private function validateRecaptcha(Request $request): bool
    {
        $captchaResponse = $request->request->get('g-recaptcha-response');
        if (!$captchaResponse) {
            return false; // Validation du CAPTCHA échouée
        }

        $client = HttpClient::create();
        $response = $client->request('POST', 'https://www.google.com/recaptcha/api/siteverify', [
            'body' => [
                'secret' => 'YOUR_RECAPTCHA_SECRET_KEY',
                'response' => $captchaResponse,
                'remoteip' => $request->getClientIp(),
            ],
        ]);

        $content = $response->toArray();
        return isset($content['success']) && $content['success'];
    }


    #[Route('/{id}/edit', name: 'app_edit', methods: ['GET', 'POST'])]
    public function edit(Request $request, User $user, EntityManagerInterface $entityManager): Response
    {
        $form = $this->createForm(UserType::class, $user);
        $form->handleRequest($request);

        if ($form->isSubmitted() && $form->isValid()) {
            $entityManager->flush();

            return $this->redirectToRoute('app_tables', [], Response::HTTP_SEE_OTHER);
        }

        return $this->renderForm('admin/register/register.html.twig', [
            'user' => $user,
            'form' => $form,
        ]);
    }

    #[Route('/delete/{id}', name: 'app_delete', methods: ['POST'])]
    public function delete(Request $request, User $user, EntityManagerInterface $entityManager): Response
    {
        if ($this->isCsrfTokenValid('delete'.$user->getId(), $request->request->get('_token'))) {
            $entityManager->remove($user);
            $entityManager->flush();
        }

        return $this->redirectToRoute('app_tables', [], Response::HTTP_SEE_OTHER);
    }

    #[Route('/verify/email', name: 'app_verify_email')]
    public function verifyUserEmail(Request $request, TranslatorInterface $translator, UserRepository $userRepository): Response
    {
        $id = $request->query->get('id');

        if (null === $id) {
            return $this->redirectToRoute('app_register');
        }

        $user = $userRepository->find($id);

        if (null === $user) {
            return $this->redirectToRoute('app_register');
        }

        try {
            $this->emailVerifier->handleEmailConfirmation($request, $user);
        } catch (VerifyEmailExceptionInterface $exception) {
            $this->addFlash('verify_email_error', $translator->trans($exception->getReason(), [], 'VerifyEmailBundle'));
            return $this->redirectToRoute('app_register');
        }

        $this->addFlash('success', 'Your email address has been verified.');
        return $this->redirectToRoute('app_login');
    }
}
