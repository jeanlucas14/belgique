<?php

namespace App\Controller;
use App\Service\Uploader;
use App\Entity\User;
use App\Form\UserType;
use App\Entity\ResetPassword;
use App\Repository\UserRepository;
use Doctrine\ORM\EntityManagerInterface;
use App\Repository\ResetPasswordRepository;
use DateTime;
use Symfony\Bridge\Twig\Mime\TemplatedEmail;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Mailer\MailerInterface;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Validator\Constraints\NotBlank; 
use Symfony\Component\Validator\Constraints\Length; 
use Symfony\Component\Form\Extension\Core\Type\EmailType;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\Form\Extension\Core\Type\PasswordType;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasher;
use Symfony\Component\Security\Http\Authentication\AuthenticationUtils;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\RateLimiter\RateLimiterFactory;
use Symfony\Component\Security\Http\Authenticator\FormLoginAuthenticator;
use Symfony\Component\Security\Http\Authentication\UserAuthenticatorInterface;

class SecurityController extends AbstractController
{

    public function __construct(
        private FormLoginAuthenticator $authenticator
    ) {
    }

    #[Route('/signup', name: 'signup')]
    public function signup(Uploader $upload,UserAuthenticatorInterface $userAuthenticator, Request $request, EntityManagerInterface $em, UserPasswordHasherInterface $passwordHasher, MailerInterface $mailer): Response
    {
        $user = new User;
        $userForm = $this->createForm(UserType::class, $user);
        $userForm->handleRequest($request);
        if ($userForm->isSubmitted() && $userForm->isValid()) {
          $picture = $userForm->get('pictureFile')->getData();
      
         $user->setPicture($upload->uploadProfileImage($picture));
            $hash = $passwordHasher->hashPassword($user, $user->getPassword());
            $user->setPassword($hash);
            $em->persist($user);
            $em->flush();
            $this->addFlash('success', 'Bienvenue sur Wonder !');

            $email = new TemplatedEmail();
            $email->to($user->getEmail())
                ->subject('Bienvenue sur Wonder')
                ->htmlTemplate('@email_templates/welcome.html.twig')
                ->context([
                    'username' => $user->getFirstname()
                ]);
            $mailer->send($email);

            return $userAuthenticator->authenticateUser($user, $this->authenticator, $request);
        }
        return $this->render('security/signup.html.twig', ['form' => $userForm->createView()]);
    }


    #[Route("/login", name: "login")]
    public function login(AuthenticationUtils $authenticationUtils): Response
    {
        if ($this->getUser()) {
            return $this->redirectToRoute('home');
        }
        $error = $authenticationUtils->getLastAuthenticationError();
        $lastUsername = $authenticationUtils->getLastUsername();
        return $this->render('security/login.html.twig', ['last_username' => $lastUsername, 'error' => $error]);
    }

    #[Route("/logout", name: "logout")]
    public function logout()
    {
    }
    //reinitialisation du mote de passec
  
      #[Route('/reset-password/{token}', name: 'reset-password')]
      public function resetPassword(RateLimiterFactory $passwordRecoveryLimiter,UserPasswordHasherInterface $userPasswordHasher, Request $request,EntityManagerInterface $em,string $token, ResetPasswordRepository $resetPasswordRepository)
      {

          //option de securite
          $limiter = $passwordRecoveryLimiter->create($request->getClientIp());
          if (false === $limiter->consume(1)->isAccepted())
          {
            $this->addFlash('error', 'Vous devez attendre 1heure pour refaire une tentative');
            return $this->redirectToRoute('login');
          }


          //option de securite
        $resetPassword = $resetPasswordRepository->findOneBy(['token' => sha1($token)]);
        if (!$resetPassword ||$resetPassword->getExpiredAt() < new DateTime('now')) {
          if ($resetPassword){
              $em->remove($resetPassword);
              $em->flush();
          }
        
          $this->addFlash('error', 'votre demande est expire veuillez refaire une demande');
          return $this->redirectToRoute('login');
        }

        //creation du formulaire pour le nouveau mot de passe
        $passwordForm = $this->createFormBuilder()
                ->add('password', PasswordType::class, [
                  'label' => 'Nouveau Mot de passe',
                  'constraints' => [
                    new Length([
                      'min' => 6,
                      'minMessage' => 'le mot de passe doit faire au moins 6 caracteres.'
                    ]),
                    new NotBlank([
                      'message' => 'veuilez renseigner un mot de passe '
                    ])
                  ]
                ])
                ->getForm();

                $passwordForm->handleRequest($request);
                if ($passwordForm->isSubmitted() && $passwordForm->isValid())
                {
                  //recuper le nouveau password
                  $password = $passwordForm->get('password')->getData();
                  //recuperer lu'tilisateur
                  $user = $resetPassword->getUser();
                  $hash = $userPasswordHasher->hashPassword($user, $password);
                    $user->setPassword($hash);
                    //quand le mot de passe et change supprimer le token
                    $em->remove($resetPassword);
                    $em->flush(); //sauvegarde
                    $this->addFlash('success','Votre mot de passe a été modifié');
                    return $this->redirectToRoute('login');


                }

                
        return $this->render('security/reset_password_form.html.twig', [
          'form' => $passwordForm->createView()
        ]);
      }
    
      #[Route('/reset-password-request', name: 'reset-password-request')]
      public function resetPasswordRequest(RateLimiterFactory $passwordRecoveryLimiter, MailerInterface $mailer, Request $request, UserRepository $userRepository, ResetPasswordRepository $resetPasswordRepository, EntityManagerInterface $em)
      {
          //option de securite
          $limiter = $passwordRecoveryLimiter->create($request->getClientIp());
          if (false === $limiter->consume(1)->isAccepted())
          {
            $this->addFlash('error', 'Vous devez attendre 1heure pour refaire une tentative');
            return $this->redirectToRoute('login');
          }


          //option de securite
        $emailForm = $this->createFormBuilder()->add('email', EmailType::class, [
          'constraints' => [
            new NotBlank([
              'message' => 'Veuillez renseigner votre email'
            ])
          ]
        ])->getForm();
        $emailForm->handleRequest($request);
        if ($emailForm->isSubmitted() && $emailForm->isValid()) {
          $emailValue = $emailForm->get('email')->getData();
          $user = $userRepository->findOneBy(['email' => $emailValue]);
          if ($user) {
            $oldResetPassword = $resetPasswordRepository->findOneBy(['user' => $user]);
            if ($oldResetPassword) {
              $em->remove($oldResetPassword);
              $em->flush();
            }
            $resetPassword = new ResetPassword();
            $resetPassword->setUser($user);
            $resetPassword->setExpiredAt(new \DateTimeImmutable('+2 hours'));
            $token = substr(str_replace(['+', '/', '='], '', base64_encode(random_bytes(30))), 0, 20);
         
            $resetPassword->setToken(sha1($token));
            $em->persist($resetPassword);
            $em->flush();
            $email = new TemplatedEmail();
            $email->to($emailValue)
              ->subject('Demande de réinitialisation de mot de passe')
              ->htmlTemplate('@email_templates/reset_password_request.html.twig')
              ->context([
                'token' => $token
              ]);
            $mailer->send($email);
          }
          $this->addFlash('success', 'Un email vous a été envoyé pour réinitialiser votre mot de passe');
          return $this->redirectToRoute('home');
        }
    
        return $this->render('security/reset_password_request.html.twig', [
          'form' => $emailForm->createView()
        ]);
      }
    }