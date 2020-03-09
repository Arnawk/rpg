<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\User;
class UserController extends Controller
{
    public function createUser ( Request $request ) {
        return User::create($request->all);
    } 
}
