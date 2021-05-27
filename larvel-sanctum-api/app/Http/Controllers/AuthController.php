<?php

namespace App\Http\Controllers;

use App\Models\User;
use App\Http\Requests\RegisterValidationRequest;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;

class AuthController extends Controller
{
    public function register(RegisterValidationRequest $request)
    {
        $fields =  $request->validated();

        //Check Email 
        $user = User::where('email', $fields['email'])->first();

        //Check password
        if ($user) {
            return response([
                'message' => 'Email is taken', 401
            ]);
        }
        $user = User::create([
            'name' => $fields['name'],
            'email' => $fields['email'],
            'password' => bcrypt($fields['password'])

        ]);

        $token = $user->createToken('user_token')->plainTextToken;

        $response = [
            'user' => $user,
            'token' => $token
        ];

        return response($response, 201);
    }

    public function logout(Request $request)
    {
        auth()->user()->tokens()->delete();

        return ['message' => 'Logged out'];
    }

    public function login(Request $request)
    {
        $fields =  $request->validate(
            [
                'email' => ['required'], ['string'],
                'password' => ['required'], ['string']
            ]
        );

        //Check Email 
        $user = User::where('email', $fields['email'])->first();

        //Check password
        if (!$user || !Hash::check($fields['password'], $user->password)) {
            return response([
                'message' => 'Invalid Cred', 401
            ]);
        }

        $token = $user->createToken('user_token')->plainTextToken;

        $response = [
            'user' => $user,
            'token' => $token
        ];

        return response($response, 201);
    }
}
