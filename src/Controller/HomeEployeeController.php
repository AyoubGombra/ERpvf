<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class HomeEployeeController extends AbstractController
{
    #[Route('/home/eployee', name: 'app_home_eployee')]
    public function index(): Response
    {
        return $this->render('employee/home_eployee/HomeEployee.html.twig', [
            'controller_name' => 'HomeEployeeController',
        ]);
    }
}
