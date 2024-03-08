<?php

namespace App\Form;

use App\Entity\User;
use Symfony\Component\Form\AbstractType;
use Symfony\Component\Form\Extension\Core\Type\ChoiceType;
use Symfony\Component\Form\Extension\Core\Type\EmailType;
use Symfony\Component\Form\Extension\Core\Type\PasswordType;
use Symfony\Component\Form\Extension\Core\Type\SubmitType;
use Symfony\Component\Form\Extension\Core\Type\TextType;
use Symfony\Component\Form\FormBuilderInterface;
use Symfony\Component\OptionsResolver\OptionsResolver;
use VictorPrdh\RecaptchaBundle\Form\ReCaptchaType;

class UserType extends AbstractType
{
    public function buildForm(FormBuilderInterface $builder, array $options): void
    {
        $builder
            ->add('email', EmailType::class, [
                'label' => 'mail',
                'attr' => ['class' => 'form-control']
            ])
            ->add('roleUser', ChoiceType::class, [
                'choices' => [
                    'Administrateur' => 'Administrateur',
                    'Employee' => 'Employee',
                ],
                'placeholder' => 'Choose a role',
                'required' => true,
                'attr' => ['class' => 'form-control']
            ])
            ->add('password', PasswordType::class)
            ->add('name', TextType::class)
            ->add('prenom', TextType::class)
            ->add('salaire', TextType::class)
            ->add('departement', ChoiceType::class, [
                'choices' => [
                    'Département administrateur' => 'administrateur',
                    'Département fournisseur' => 'fournisseur',
                    'Département livraison' => 'livraison',
                    'Département produit' => 'produit',
                    'Département facture' => 'facture',
                    'Département client' => 'client',
                ],
                'placeholder' => 'Choose a department',
                'required' => true,
                'attr' => ['class' => 'form-control'],
            ])
            ->add('captcha', ReCaptchaType::class)
            ->add('save', SubmitType::class, [
                'label' => 'Submit',
                'attr' => ['class' => 'btn btn-primary btn-block']
            ]);
    }

    public function configureOptions(OptionsResolver $resolver): void
    {
        $resolver->setDefaults([
            'data_class' => User::class,
        ]);
    }
}
