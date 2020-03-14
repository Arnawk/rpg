<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\User;
use Illuminate\Support\Facades\Auth;
use Carbon\Carbon;
use Illuminate\Support\Facades\Log;
use GuzzleHttp\Client;

class UserController extends Controller
{
    public function createUser ( Request $request ) {
        $data = [];
        $data['name'] = $request->name;
        $data['email'] = $request->email;
        $data['password'] = $request->password;
        $user = User::create($data);
        return response()->json($user, 201);
    } 
    public function login (Request $request) {
        Log::info("Login request received");
        $request->validate([
            'email'    => 'required|string|email',
            'password' => 'required|string',
        ]);

        $credentials = request(['email', 'password']);
        //decode password from base64
        $credentials['password'] = $credentials['password'];

        if ( !Auth::attempt($credentials) ) {
            Log::info("Unauthorized login");
            return response()->json([
                'status'  => 401,
                'payload' => [
                    'request_at'     => Carbon::now(),
                    'status_message' => 'unauthorized, bad credentials.',
                ],
            ]);
        }

        $user = $request->user();
        $tokenResult = $user->createToken('Personal Access Token');
        $token = $tokenResult->token;
        $token->expires_at = Carbon::now()->addMinutes(30);
        $token->save();
        return ResponseUtility::success_response([
            'access_token'   => $tokenResult->accessToken,
            'name'           => $user->name,
            'request_at'     => Carbon::now(),
            'expires_at'     => Carbon::parse(
                $tokenResult->token->expires_at
            )->toDateTimeString(),
            'status_message' => 'token generated successfully',

        ]);
}
